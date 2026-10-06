package service

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
)

const (
	EventLogin          = "login"
	EventLoginFailed    = "login_failed"
	EventLogout         = "logout"
	EventSSOSession     = "sso_session_triggered"
	EventBruteforce     = "bruteforce_detected"
	EventForgotPassword = "forgot_password"
	EventChangePassword = "change_password"
	EventPasswordReset  = "password_reset"
	EventUserRegistered = "user_registered"
	EventEmailVerified  = "email_verified"
	EventUserDisabled   = "user_disabled"
	EventWebhookTest    = "webhook.test"
)

var webhookEvents = map[string]struct{}{
	EventLogin:          {},
	EventLoginFailed:    {},
	EventLogout:         {},
	EventSSOSession:     {},
	EventBruteforce:     {},
	EventForgotPassword: {},
	EventChangePassword: {},
	EventPasswordReset:  {},
	EventUserRegistered: {},
	EventEmailVerified:  {},
	EventUserDisabled:   {},
	EventWebhookTest:    {},
	"*":                 {},
}

func KnownWebhookEvents() []string {
	return []string{
		EventLogin,
		EventLoginFailed,
		EventLogout,
		EventSSOSession,
		EventBruteforce,
		EventForgotPassword,
		EventChangePassword,
		EventPasswordReset,
		EventUserRegistered,
		EventEmailVerified,
		EventUserDisabled,
	}
}

type WebhookDispatcher struct {
	repo  *repository.WebhookRepository
	http  *http.Client
	fetch *config.Config
}

func (d *WebhookDispatcher) SetFetchConfig(cfg *config.Config) {
	if d != nil {
		d.fetch = cfg
	}
}

func NewWebhookDispatcher(repo *repository.WebhookRepository) *WebhookDispatcher {
	return &WebhookDispatcher{
		repo: repo,
		http: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type WebhookInput struct {
	URL         string
	Secret      string
	Events      []string
	Enabled     *bool
	Description string
}

func (d *WebhookDispatcher) Create(in WebhookInput) (*models.Webhook, error) {
	if err := d.checkURL(in.URL); err != nil {
		return nil, err
	}
	events, err := normalizeEvents(in.Events)
	if err != nil {
		return nil, err
	}
	secret := strings.TrimSpace(in.Secret)
	if secret == "" {
		secret, err = randomSecret()
		if err != nil {
			return nil, err
		}
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	now := time.Now()
	hook := &models.Webhook{
		ID:          uuid.NewString(),
		URL:         in.URL,
		Secret:      secret,
		Events:      events,
		Enabled:     enabled,
		Description: in.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := d.repo.Create(hook); err != nil {
		return nil, err
	}
	return hook, nil
}

func (d *WebhookDispatcher) Update(id string, in WebhookInput) (*models.Webhook, error) {
	hook, err := d.repo.Get(id)
	if err != nil {
		return nil, err
	}
	if in.URL != "" {
		if err := d.checkURL(in.URL); err != nil {
			return nil, err
		}
		hook.URL = in.URL
	}
	if in.Events != nil {
		events, err := normalizeEvents(in.Events)
		if err != nil {
			return nil, err
		}
		hook.Events = events
	}
	if strings.TrimSpace(in.Secret) != "" {
		hook.Secret = strings.TrimSpace(in.Secret)
	}
	if in.Enabled != nil {
		hook.Enabled = *in.Enabled
	}
	if in.Description != "" {
		hook.Description = in.Description
	}
	if err := d.repo.Update(hook); err != nil {
		return nil, err
	}
	return hook, nil
}

func (d *WebhookDispatcher) List() ([]*models.Webhook, error) {
	return d.repo.List()
}

func (d *WebhookDispatcher) Get(id string) (*models.Webhook, error) {
	return d.repo.Get(id)
}

func (d *WebhookDispatcher) Delete(id string) error {
	return d.repo.Delete(id)
}

func (d *WebhookDispatcher) Test(id string) error {
	hook, err := d.repo.Get(id)
	if err != nil {
		return err
	}
	body := payload(EventWebhookTest, map[string]any{"webhook_id": hook.ID})
	return d.post(hook, EventWebhookTest, body)
}

func (d *WebhookDispatcher) Emit(event string, data map[string]any) {
	if d == nil || d.repo == nil {
		return
	}
	hooks, err := d.repo.List()
	if err != nil {
		log.Printf("webhooks: list: %v", err)
		return
	}
	body := payload(event, data)
	for _, hook := range hooks {
		if !hook.Wants(event) {
			continue
		}
		if err := d.post(hook, event, body); err != nil {
			log.Printf("webhook %s %s: %v", hook.ID, event, err)
		}
	}
}

func payload(event string, data map[string]any) []byte {
	if data == nil {
		data = map[string]any{}
	}
	raw, err := json.Marshal(map[string]any{
		"id":         uuid.NewString(),
		"event":      event,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"data":       data,
	})
	if err != nil {
		return []byte(`{"event":"error"}`)
	}
	return raw
}

func (d *WebhookDispatcher) post(hook *models.Webhook, event string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(hook.Secret))
	_, _ = mac.Write([]byte(ts))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "oauth-impl-webhooks")
	req.Header.Set("X-Webhook-Event", event)
	req.Header.Set("X-Webhook-Timestamp", ts)
	req.Header.Set("X-Webhook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	if d.fetch != nil {
		_, status, err := FetchSafe(req.Context(), d.fetch, http.MethodPost, hook.URL, bytes.NewReader(body), req.Header)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("receiver returned %d", status)
		}
		return nil
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("receiver returned %d", resp.StatusCode)
	}
	return nil
}

func (d *WebhookDispatcher) checkURL(raw string) error {
	if d != nil && d.fetch != nil {
		return ValidateFetchTarget(d.fetch, raw)
	}
	return validateWebhookURL(raw)
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("webhook url must be an absolute http or https URL")
	}
	return nil
}

func normalizeEvents(events []string) ([]string, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("at least one event is required")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(events))
	for _, event := range events {
		event = strings.TrimSpace(event)
		if _, ok := webhookEvents[event]; !ok {
			return nil, fmt.Errorf("unknown webhook event %q", event)
		}
		if _, ok := seen[event]; ok {
			continue
		}
		seen[event] = struct{}{}
		out = append(out, event)
	}
	return out, nil
}

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
