package controller

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/handlers/oauth"
	"github.com/bravo68web/oauth-impl/internal/service"
)

type WebController struct {
	userSvc      *service.UserService
	totpSvc      *service.TOTPService
	cfg          *config.Config
	oauthHandler *oauth.Handler
	sessions     map[string]*Session
	mu           sync.RWMutex
	templates    *template.Template
}

type Session struct {
	UserID        string
	Username      string
	Authenticated bool
	MFAVerified   bool
}

func NewWebController(userSvc *service.UserService, totpSvc *service.TOTPService, cfg *config.Config, templateFS embed.FS, oauthHandler *oauth.Handler) (*WebController, error) {
	funcMap := template.FuncMap{
		"split": strings.Split,
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "internal/templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &WebController{
		userSvc:      userSvc,
		totpSvc:      totpSvc,
		cfg:          cfg,
		oauthHandler: oauthHandler,
		sessions:     make(map[string]*Session),
		templates:    tmpl,
	}, nil
}

func (c *WebController) getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessions[cookie.Value]
}

func (c *WebController) setSession(w http.ResponseWriter, session *Session) string {
	sessionID := fmt.Sprintf("%d", len(c.sessions)+1)
	c.mu.Lock()
	c.sessions[sessionID] = session
	c.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	return sessionID
}

// buildAuthorizeURL constructs /oauth/authorize URL with all OAuth params
func (c *WebController) buildAuthorizeURL(params map[string]string) string {
	parts := []string{}
	for k, v := range params {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return "/oauth/authorize?" + strings.Join(parts, "&")
}

// extractOAuthParams extracts OAuth params from request
func extractOAuthParams(r *http.Request) map[string]string {
	return map[string]string{
		"client_id":             r.URL.Query().Get("client_id"),
		"redirect_uri":          r.URL.Query().Get("redirect_uri"),
		"response_type":         r.URL.Query().Get("response_type"),
		"scope":                 r.URL.Query().Get("scope"),
		"state":                 r.URL.Query().Get("state"),
		"nonce":                 r.URL.Query().Get("nonce"),
		"code_challenge":        r.URL.Query().Get("code_challenge"),
		"code_challenge_method": r.URL.Query().Get("code_challenge_method"),
	}
}

// extractOAuthParamsFromForm extracts OAuth params from POST form
func extractOAuthParamsFromForm(r *http.Request) map[string]string {
	return map[string]string{
		"client_id":             r.FormValue("client_id"),
		"redirect_uri":          r.FormValue("redirect_uri"),
		"response_type":         r.FormValue("response_type"),
		"scope":                 r.FormValue("scope"),
		"state":                 r.FormValue("state"),
		"nonce":                 r.FormValue("nonce"),
		"code_challenge":        r.FormValue("code_challenge"),
		"code_challenge_method": r.FormValue("code_challenge_method"),
	}
}

// oauthTemplateData creates template data with OAuth params
func oauthTemplateData(params map[string]string, extra map[string]interface{}) map[string]interface{} {
	data := map[string]interface{}{
		"ClientID":             params["client_id"],
		"RedirectURI":          params["redirect_uri"],
		"ResponseType":         params["response_type"],
		"Scope":                params["scope"],
		"State":                params["state"],
		"Nonce":                params["nonce"],
		"CodeChallenge":        params["code_challenge"],
		"CodeChallengeMethod":  params["code_challenge_method"],
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// ──────────────────────────────────────────────
// Login Flow
// ──────────────────────────────────────────────

func (c *WebController) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	params := extractOAuthParams(r)
	data := oauthTemplateData(params, map[string]interface{}{
		"Error": "",
	})
	_ = c.templates.ExecuteTemplate(w, "login.html", data)
}

func (c *WebController) HandleLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	params := extractOAuthParamsFromForm(r)

	user, err := c.userSvc.Authenticate(username, password)
	if err != nil {
		data := oauthTemplateData(params, map[string]interface{}{
			"Error": "Invalid credentials",
		})
		_ = c.templates.ExecuteTemplate(w, "login.html", data)
		return
	}

	// Check if MFA is required server-wide
	if c.cfg.Security.MFA.Required {
		mfaEnabled, _ := c.totpSvc.IsMFAEnabled(user.ID)
		if !mfaEnabled {
			// MFA required but not enrolled → redirect to enrollment
			session := &Session{
				UserID:        user.ID,
				Username:      user.Username,
				Authenticated: true,
				MFAVerified:   false,
			}
			c.setSession(w, session)

			// Redirect to MFA enrollment with OAuth params
			enrollURL := "/mfa/enroll?" + r.Form.Encode()
			http.Redirect(w, r, enrollURL, http.StatusFound)
			return
		}

		// MFA required and enrolled → show MFA verification
		session := &Session{
			UserID:        user.ID,
			Username:      user.Username,
			Authenticated: true,
			MFAVerified:   false,
		}
		c.setSession(w, session)

		data := oauthTemplateData(params, map[string]interface{}{
			"Error": "",
		})
		_ = c.templates.ExecuteTemplate(w, "mfa.html", data)
		return
	}

	// No MFA required → set session and redirect to authorize
	c.oauthHandler.SetSession(w, user.ID, user.Username)
	authorizeURL := c.buildAuthorizeURL(params)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// ──────────────────────────────────────────────
// MFA Verification Flow
// ──────────────────────────────────────────────

func (c *WebController) HandleMFA(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.FormValue("code")
	params := extractOAuthParamsFromForm(r)

	session := c.getSession(r)
	if session == nil {
		http.Redirect(w, r, "/login?"+r.Form.Encode(), http.StatusFound)
		return
	}

	valid, err := c.totpSvc.VerifyLogin(session.UserID, code)
	if err != nil || !valid {
		data := oauthTemplateData(params, map[string]interface{}{
			"Error": "Invalid TOTP code",
		})
		_ = c.templates.ExecuteTemplate(w, "mfa.html", data)
		return
	}

	// MFA verified → set session and redirect to authorize
	session.MFAVerified = true
	c.mu.Lock()
	c.sessions[session.UserID] = session
	c.mu.Unlock()

	c.oauthHandler.SetSession(w, session.UserID, session.Username)
	authorizeURL := c.buildAuthorizeURL(params)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// ──────────────────────────────────────────────
// MFA Enrollment Flow
// ──────────────────────────────────────────────

func (c *WebController) HandleMFAEnrollPage(w http.ResponseWriter, r *http.Request) {
	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	params := extractOAuthParams(r)

	result, err := c.totpSvc.EnableMFA(session.UserID, session.Username)
	if err != nil {
		data := oauthTemplateData(params, map[string]interface{}{
			"Error": "Failed to generate MFA enrollment",
		})
		_ = c.templates.ExecuteTemplate(w, "mfa_enroll.html", data)
		return
	}

	data := oauthTemplateData(params, map[string]interface{}{
		"QRCodeBase64": result.QRBase64,
		"Secret":       result.Secret,
		"Issuer":       c.cfg.Security.MFA.Issuer,
		"Username":     session.Username,
		"Error":        "",
	})

	_ = c.templates.ExecuteTemplate(w, "mfa_enroll.html", data)
}

func (c *WebController) HandleMFAEnrollVerify(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.FormValue("code")
	secret := r.FormValue("secret")
	params := extractOAuthParamsFromForm(r)

	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.Form.Encode(), http.StatusFound)
		return
	}

	if err := c.totpSvc.ConfirmMFA(session.UserID, code); err != nil {
		result, _ := c.totpSvc.EnableMFA(session.UserID, session.Username)
		data := oauthTemplateData(params, map[string]interface{}{
			"QRCodeBase64": result.QRBase64,
			"Secret":       secret,
			"Issuer":       c.cfg.Security.MFA.Issuer,
			"Username":     session.Username,
			"Error":        "Invalid code. Please try again.",
		})
		_ = c.templates.ExecuteTemplate(w, "mfa_enroll.html", data)
		return
	}

	// MFA enrolled successfully → set session and redirect to authorize
	session.MFAVerified = true
	c.oauthHandler.SetSession(w, session.UserID, session.Username)
	authorizeURL := c.buildAuthorizeURL(params)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// ──────────────────────────────────────────────
// Registration Flow
// ──────────────────────────────────────────────

func (c *WebController) HandleRegisterPage(w http.ResponseWriter, r *http.Request) {
	params := extractOAuthParams(r)
	data := oauthTemplateData(params, map[string]interface{}{
		"Error": "",
	})
	_ = c.templates.ExecuteTemplate(w, "register.html", data)
}

func (c *WebController) HandleRegister(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	params := extractOAuthParamsFromForm(r)

	_, err := c.userSvc.CreateUser(username, password, email, "")
	if err != nil {
		data := oauthTemplateData(params, map[string]interface{}{
			"Error": err.Error(),
		})
		_ = c.templates.ExecuteTemplate(w, "register.html", data)
		return
	}

	// Registration successful → redirect to login with OAuth params preserved
	loginURL := "/login?" + r.Form.Encode()
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// ──────────────────────────────────────────────
// Consent Flow
// ──────────────────────────────────────────────

func (c *WebController) HandleConsentPage(w http.ResponseWriter, r *http.Request) {
	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	params := extractOAuthParams(r)
	data := oauthTemplateData(params, map[string]interface{}{
		"Username": session.Username,
		"Scopes":   strings.Split(params["scope"], " "),
	})

	_ = c.templates.ExecuteTemplate(w, "consent.html", data)
}

func (c *WebController) HandleConsent(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.FormValue("action")
	params := extractOAuthParamsFromForm(r)

	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.Form.Encode(), http.StatusFound)
		return
	}

	if action == "deny" {
		redirectURI := params["redirect_uri"]
		state := params["state"]
		errorURL := redirectURI
		if strings.Contains(errorURL, "?") {
			errorURL += "&"
		} else {
			errorURL += "?"
		}
		errorURL += "error=access_denied&error_description=User+denied+the+request"
		if state != "" {
			errorURL += "&state=" + state
		}
		http.Redirect(w, r, errorURL, http.StatusFound)
		return
	}

	// Consent approved → redirect to authorize
	authorizeURL := c.buildAuthorizeURL(params)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}
