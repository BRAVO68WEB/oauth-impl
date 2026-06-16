package controller

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/handlers/oauth"
	"github.com/bravo68web/oauth-impl/internal/service"
)

type WebController struct {
	userSvc      *service.UserService
	totpSvc      *service.TOTPService
	cfg          *config.Config
	oauthHandler *oauth.Handler
	templates    *template.Template
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
		templates:    tmpl,
	}, nil
}

func (c *WebController) getSession(r *http.Request) *oauth.Session {
	return c.oauthHandler.GetSession(r)
}

// buildAuthorizeURL constructs /oauth/authorize URL with all OAuth params
func (c *WebController) buildAuthorizeURL(params map[string]string) string {
	parts := []string{}
	for k, v := range params {
		if v != "" {
			parts = append(parts, k+"="+url.QueryEscape(v))
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
		"request_uri":           r.URL.Query().Get("request_uri"),
		"prompt":                r.URL.Query().Get("prompt"),
		"login_hint":            r.URL.Query().Get("login_hint"),
		"resource":              r.URL.Query().Get("resource"),
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
		"request_uri":           r.FormValue("request_uri"),
		"prompt":                r.FormValue("prompt"),
		"login_hint":            r.FormValue("login_hint"),
		"resource":              r.FormValue("resource"),
	}
}

// oauthTemplateData creates template data with OAuth params
func oauthTemplateData(params map[string]string, extra map[string]interface{}) map[string]interface{} {
	data := map[string]interface{}{
		"ClientID":            params["client_id"],
		"RedirectURI":         params["redirect_uri"],
		"ResponseType":        params["response_type"],
		"Scope":               params["scope"],
		"State":               params["state"],
		"Nonce":               params["nonce"],
		"CodeChallenge":       params["code_challenge"],
		"CodeChallengeMethod": params["code_challenge_method"],
		"RequestURI":          params["request_uri"],
		"Prompt":              params["prompt"],
		"LoginHint":           params["login_hint"],
		"Resource":            params["resource"],
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
		"Error":      "",
		"LoginHint":  params["login_hint"],
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
			c.oauthHandler.SetSessionWithMFA(w, user.ID, user.Username, false)

			// Redirect to MFA enrollment with OAuth params
			enrollURL := "/mfa/enroll?" + r.Form.Encode()
			http.Redirect(w, r, enrollURL, http.StatusFound)
			return
		}

		// MFA required and enrolled → show MFA verification
		c.oauthHandler.SetSessionWithMFA(w, user.ID, user.Username, false)

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

	// MFA verified → create new session with MFA verified
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

	// MFA enrolled successfully → set session with MFA verified and redirect to authorize
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

	// If PAR, fetch stored params and merge (scope, redirect_uri, etc. are in PAR, not URL)
	if requestURI := params["request_uri"]; requestURI != "" {
		if par, err := c.oauthHandler.GetPARParams(requestURI); err == nil {
			for k, v := range par {
				if params[k] == "" {
					params[k] = v
				}
			}
		}
	}

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

	// If PAR, fetch stored params to get real scope, redirect_uri, etc.
	if requestURI := params["request_uri"]; requestURI != "" {
		if par, err := c.oauthHandler.GetPARParams(requestURI); err == nil {
			for k, v := range par {
				if params[k] == "" {
					params[k] = v
				}
			}
		}
	}

	// Consent approved → persist consent
	clientID := params["client_id"]
	scope := params["scope"]
	if clientID != "" && scope != "" {
		scopes := strings.Split(scope, " ")
		_ = c.oauthHandler.SaveConsent(session.UserID, clientID, scopes)
	}

	// Redirect to authorize
	authorizeURL := c.buildAuthorizeURL(params)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}
