package oauth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/service"
)

const cimdTTL = 5 * time.Minute

type cimdCache struct {
	mu    sync.Mutex
	items map[string]cimdCacheEntry
}

type cimdCacheEntry struct {
	client  *models.Client
	fetched time.Time
}

func newCIMDCache() *cimdCache {
	return &cimdCache{items: map[string]cimdCacheEntry{}}
}

func (c *cimdCache) get(id string) (*models.Client, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[id]
	if !ok || time.Since(entry.fetched) > cimdTTL {
		return nil, false
	}
	return entry.client, true
}

func (c *cimdCache) put(client *models.Client) {
	if c == nil || client == nil {
		return
	}
	c.mu.Lock()
	c.items[client.ID] = cimdCacheEntry{client: client, fetched: time.Now()}
	c.mu.Unlock()
}

func (h *Handler) SetAudit(a *service.AuditLog) {
	if h != nil {
		h.audit = a
	}
}

// resolveClient loads a client for authorize and token requests.
// An HTTPS client_id is a Client ID Metadata Document.
// A DCR client is unauthorized unless the tenant and the row both allow it.
func (h *Handler) resolveClient(clientID, redirectURI string) (*models.Client, string, string) {
	if clientID == "" {
		return nil, "invalid_client", "Client not found"
	}
	if isCIMDURL(clientID) {
		return h.resolveCIMD(clientID, redirectURI)
	}
	client, err := h.clientRepo.GetByID(clientID)
	if err != nil || client == nil {
		return nil, "invalid_client", "Client not found"
	}
	if code, desc := h.gateDCR(client); code != "" {
		return nil, code, desc
	}
	return client, "", ""
}

func (h *Handler) gateDCR(client *models.Client) (string, string) {
	source := client.RegistrationSource
	if source == "" {
		source = "management"
	}
	if source != "dcr" {
		return "", ""
	}
	tenant := h.cfg != nil && h.cfg.Registration.DCREnabled
	if !tenant || !client.DCREnabled {
		return "unauthorized_client", "Dynamically registered client is disabled"
	}
	return "", ""
}

func isCIMDURL(id string) bool {
	parsed, err := url.Parse(id)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

func (h *Handler) resolveCIMD(clientID, redirectURI string) (*models.Client, string, string) {
	if h.cfg == nil || !h.cfg.Registration.CIMDEnabled {
		return nil, "invalid_client", "Client ID metadata documents are disabled"
	}
	existing, err := h.clientRepo.GetByID(clientID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "server_error", "Failed to load client"
	}
	if err == nil && existing != nil && !existing.CIMDEnabled {
		return nil, "invalid_client", "Client ID metadata document is disabled"
	}
	if cached, ok := h.cimd.get(clientID); ok {
		if redirectURI != "" && !containsString(cached.RedirectURIs, redirectURI) {
			return nil, "invalid_request", "redirect_uri is not listed in the client metadata"
		}
		return cached, "", ""
	}
	doc, err := service.FetchCIMD(context.Background(), h.cfg, clientID)
	if err != nil || doc == nil {
		return nil, "invalid_client", "Failed to fetch client metadata"
	}
	if doc.ClientID != clientID {
		return nil, "invalid_client", "client_id in the metadata document does not match the URL"
	}
	if redirectURI != "" && !containsString(doc.RedirectURIs, redirectURI) {
		return nil, "invalid_request", "redirect_uri is not listed in the client metadata"
	}
	client := service.ClientFromCIMD(doc)
	now := time.Now()
	client.UpdatedAt = now
	if existing != nil {
		client.CreatedAt = existing.CreatedAt
		if err := h.clientRepo.Update(client); err != nil {
			return nil, "server_error", "Failed to store client metadata"
		}
	} else {
		client.CreatedAt = now
		if err := h.clientRepo.Create(client); err != nil {
			return nil, "server_error", "Failed to store client metadata"
		}
	}
	h.cimd.put(client)
	if h.audit != nil {
		h.audit.Write("system", "cimd", "client.cimd", "client", client.ID, nil, map[string]any{"name": client.Name})
	}
	return client, "", ""
}

func (h *Handler) requireClient(w http.ResponseWriter, clientID, redirectURI string, missingStatus int) (*models.Client, bool) {
	client, code, desc := h.resolveClient(clientID, redirectURI)
	if code == "" {
		return client, true
	}
	status := missingStatus
	switch code {
	case "unauthorized_client", "invalid_request":
		status = http.StatusBadRequest
	case "server_error":
		status = http.StatusInternalServerError
	}
	writeTokenError(w, status, code, desc)
	return nil, false
}
