package oauth

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/branding"
	"github.com/bravo68web/oauth-impl/internal/cache"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

type Handler struct {
	clientRepo   *repository.ClientRepository
	userRepo     *repository.UserRepository
	tokenRepo    *repository.TokenRepository
	authCodeRepo *repository.AuthCodeRepository
	deviceRepo   *repository.DeviceCodeRepository
	cibaRepo     *repository.CIBARepository
	parRepo      *repository.PARRepository
	consentRepo  *repository.ConsentRepository
	dpopSvc      *service.DPoPService
	mtlsSvc      *service.MTLSService
	jarSvc       *service.JARService
	cfg          *config.Config
	q            queue.Queue
	oidcHandler  *oidc.Handler
	userSvc      *service.UserService
	sessions     *service.SessionService
	logout       *service.LogoutService
	logins       LoginRecorder
	pages        *template.Template
	hooks        *service.WebhookDispatcher
	brandTheme   branding.Theme
	audit        *service.AuditLog
	cimd         cache.Cache
	introspect   *service.Introspector
}

type LoginRecorder interface {
	Record(user *models.User, r *http.Request, success, mfa bool)
}

type Session struct {
	ID            string
	UserID        string
	Username      string
	Authenticated bool
	MFAVerified   bool
	AuthTime      time.Time
}

func NewHandler(
	clientRepo *repository.ClientRepository,
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	authCodeRepo *repository.AuthCodeRepository,
	deviceRepo *repository.DeviceCodeRepository,
	cibaRepo *repository.CIBARepository,
	parRepo *repository.PARRepository,
	consentRepo *repository.ConsentRepository,
	dpopSvc *service.DPoPService,
	mtlsSvc *service.MTLSService,
	jarSvc *service.JARService,
	cfg *config.Config,
	q queue.Queue,
	oidcHandler *oidc.Handler,
	userSvc *service.UserService,
	sessions *service.SessionService,
	logout *service.LogoutService,
	logins LoginRecorder,
) *Handler {
	return &Handler{
		clientRepo:   clientRepo,
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		authCodeRepo: authCodeRepo,
		deviceRepo:   deviceRepo,
		cibaRepo:     cibaRepo,
		parRepo:      parRepo,
		consentRepo:  consentRepo,
		dpopSvc:      dpopSvc,
		mtlsSvc:      mtlsSvc,
		jarSvc:       jarSvc,
		cfg:          cfg,
		q:            q,
		oidcHandler:  oidcHandler,
		userSvc:      userSvc,
		sessions:     sessions,
		logout:       logout,
		logins:       logins,
		brandTheme:   branding.Prepare(cfg),
		cimd:         cache.NewMemory(),
		introspect:   service.NewIntrospector(tokenRepo, userRepo, cfg),
	}
}

func (h *Handler) ClientName(id string) string {
	if h == nil || h.clientRepo == nil || id == "" {
		return ""
	}
	client, err := h.clientRepo.GetByID(id)
	if err != nil || client == nil {
		return ""
	}
	return client.Name
}

func (h *Handler) SetCache(c cache.Cache) {
	if h != nil && c != nil {
		h.cimd = c
	}
}

func (h *Handler) SetTemplates(t *template.Template) {
	h.pages = t
}

func (h *Handler) SetWebhooks(d *service.WebhookDispatcher) {
	h.hooks = d
}

var validResponseTypes = map[string]bool{
	"code":                true,
	"token":               true,
	"id_token":            true,
	"id_token token":      true,
	"code id_token":       true,
	"code token":          true,
	"code id_token token": true,
	"none":                true,
}

func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	responseMode := r.URL.Query().Get("response_mode")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	prompt := r.URL.Query().Get("prompt")
	loginHint := r.URL.Query().Get("login_hint")
	resource := r.URL.Query().Get("resource")
	requestURI := r.URL.Query().Get("request_uri")
	request := r.URL.Query().Get("request")

	// Handle JAR - parse request JWT parameter
	if request != "" {
		if clientID == "" {
			// Quick parse to get client_id from JWT
			parser := jwt.NewParser(jwt.WithoutClaimsValidation())
			token, _, err := parser.ParseUnverified(request, jwt.MapClaims{})
			if err == nil {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					if cid, ok := claims["client_id"].(string); ok {
						clientID = cid
					}
				}
			}
		}

		if clientID != "" {
			client, code, _ := h.resolveClient(clientID, redirectURI)
			if code == "" && client != nil && h.jarSvc != nil {
				claims, err := h.jarSvc.ValidateRequestObject(request, client)
				if err != nil {
					writeOAuthError(w, http.StatusBadRequest, "invalid_request_object", "Invalid request JWT: "+err.Error(), "")
					return
				}

				// Merge JWT claims with query params (query params take precedence)
				if v, ok := claims["client_id"]; ok && clientID == "" {
					clientID = v
				}
				if v, ok := claims["redirect_uri"]; ok && redirectURI == "" {
					redirectURI = v
				}
				if v, ok := claims["response_type"]; ok && responseType == "" {
					responseType = v
				}
				if v, ok := claims["scope"]; ok && scope == "" {
					scope = v
				}
				if v, ok := claims["state"]; ok && state == "" {
					state = v
				}
				if v, ok := claims["nonce"]; ok && nonce == "" {
					nonce = v
				}
				if v, ok := claims["code_challenge"]; ok && codeChallenge == "" {
					codeChallenge = v
				}
				if v, ok := claims["code_challenge_method"]; ok && codeChallengeMethod == "" {
					codeChallengeMethod = v
				}
				if v, ok := claims["prompt"]; ok && prompt == "" {
					prompt = v
				}
				if v, ok := claims["login_hint"]; ok && loginHint == "" {
					loginHint = v
				}
				if v, ok := claims["resource"]; ok && resource == "" {
					resource = v
				}
			}
		}
	}

	// Handle PAR - fetch stored parameters from request_uri
	if requestURI != "" {
		par, err := h.parRepo.GetByRequestURI(requestURI)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid request_uri", state)
			return
		}

		if time.Now().After(par.ExpiresAt) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request_uri expired", state)
			return
		}

		var params map[string]string
		if err := json.Unmarshal([]byte(par.RequestParams), &params); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to parse stored request", state)
			return
		}

		if v, ok := params["client_id"]; ok && clientID == "" {
			clientID = v
		}
		if v, ok := params["redirect_uri"]; ok && redirectURI == "" {
			redirectURI = v
		}
		if v, ok := params["response_type"]; ok && responseType == "" {
			responseType = v
		}
		if v, ok := params["scope"]; ok && scope == "" {
			scope = v
		}
		if v, ok := params["state"]; ok && state == "" {
			state = v
		}
		if v, ok := params["nonce"]; ok && nonce == "" {
			nonce = v
		}
		if v, ok := params["code_challenge"]; ok && codeChallenge == "" {
			codeChallenge = v
		}
		if v, ok := params["code_challenge_method"]; ok && codeChallengeMethod == "" {
			codeChallengeMethod = v
		}
		if v, ok := params["prompt"]; ok && prompt == "" {
			prompt = v
		}
		if v, ok := params["login_hint"]; ok && loginHint == "" {
			loginHint = v
		}
		if v, ok := params["resource"]; ok && resource == "" {
			resource = v
		}
	}

	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required", "")
		return
	}

	client, code, desc := h.resolveClient(clientID, redirectURI)
	if code != "" {
		writeOAuthError(w, http.StatusBadRequest, code, desc, state)
		return
	}

	if !validResponseTypes[responseType] {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "Unsupported response_type: "+responseType, state)
		return
	}

	// RFC 6749: redirect_uri is required if multiple URIs are registered
	if redirectURI == "" && len(client.RedirectURIs) > 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required when multiple redirect URIs are registered", state)
		return
	}

	// If only one URI registered and none provided, use the registered one
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}

	if !isValidRedirectURI(redirectURI, client.RedirectURIs) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri", state)
		return
	}

	// PKCE validation (optional for conformance testing)
	needsCode := strings.Contains(responseType, "code")
	if needsCode && codeChallenge != "" {
		// Default to S256 if not specified
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}
		// Allow S256 and plain
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Only S256 and plain code_challenge_method are supported", state)
			return
		}
	}
	if needsCode && h.cfg != nil && h.cfg.Security.RequirePKCE && codeChallenge == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge is required", state)
		return
	}

	// Nonce is required for implicit/hybrid flows (response_type contains id_token)
	needsIDToken := strings.Contains(responseType, "id_token")
	if needsIDToken && nonce == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "nonce is required for implicit/hybrid flows", state)
		return
	}

	session := h.getSession(r)

	// prompt=none: no UI allowed, must already be authenticated and consented
	if prompt == "none" {
		if session == nil || !session.Authenticated {
			writeOAuthError(w, http.StatusFound, "login_required", "User must be authenticated", state)
			return
		}
		if !h.hasConsented(session.UserID, clientID, scope) {
			writeOAuthError(w, http.StatusFound, "consent_required", "User consent required", state)
			return
		}
		// Proceed directly
		h.issueAuthorizationResponse(w, r, client, session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource)
		return
	}

	// prompt=login: force re-authentication
	if prompt == "login" {
		h.clearSession(w, r)
		loginURL := "/login?" + r.URL.RawQuery
		if loginHint != "" {
			loginURL += "&login_hint=" + url.QueryEscape(loginHint)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Not authenticated: redirect to login
	if session == nil || !session.Authenticated {
		loginURL := "/login?" + r.URL.RawQuery
		if loginHint != "" {
			loginURL += "&login_hint=" + url.QueryEscape(loginHint)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// MFA check
	if !session.MFAVerified && h.cfg.Security.MFA.Required {
		mfaURL := "/login/mfa?" + r.URL.RawQuery
		http.Redirect(w, r, mfaURL, http.StatusFound)
		return
	}

	// Consent check
	if prompt == "consent" || !h.hasConsented(session.UserID, clientID, scope) {
		consentURL := "/consent?" + r.URL.RawQuery
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	h.issueAuthorizationResponse(w, r, client, session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource)
}

func (h *Handler) issueAuthorizationResponse(w http.ResponseWriter, r *http.Request, client *models.Client, session *Session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource string) {
	scopes := crypto.NormalizeScopes(scope)
	hasOpenID := containsScope(scopes, "openid")

	var code string
	var accessToken string
	var idToken string
	var err error

	needsCode := strings.Contains(responseType, "code")
	needsToken := strings.Contains(responseType, "token")
	needsIDToken := strings.Contains(responseType, "id_token")

	if needsCode {
		code, err = crypto.GenerateAuthorizationCode()
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to generate authorization code", state)
			return
		}

		familyID := uuid.New().String()
		authCode := &models.AuthorizationCode{
			Code:                code,
			ClientID:            client.ID,
			UserID:              session.UserID,
			RedirectURI:         redirectURI,
			Scopes:              scopes,
			Resource:            resource,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			FamilyID:            familyID,
			SessionID:           session.ID,
			AuthTime:            session.AuthTime,
			ExpiresAt:           time.Now().Add(h.cfg.Security.AuthorizationCodeLifetime),
			Used:                false,
		}

		if err := h.authCodeRepo.Save(authCode); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to save authorization code", state)
			return
		}
	}

	if needsToken {
		accessToken, err = h.issueAccessToken(client.ID, session.UserID, scope, "Bearer")
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token", state)
			return
		}

		accessTok := &models.AccessToken{
			Token:     accessToken,
			ClientID:  client.ID,
			UserID:    session.UserID,
			Scopes:    scopes,
			Resource:  resource,
			TokenType: "Bearer",
			ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
		}

		if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to save access token", state)
			return
		}
	}

	if h.sessions != nil && session.ID != "" {
		prior, _ := h.sessions.Clients(session.ID)
		_ = h.sessions.RecordClient(session.ID, client.ID)
		prompt := r.URL.Query().Get("prompt")
		if prompt == "" && r.Form != nil {
			prompt = r.Form.Get("prompt")
		}
		crossClient := false
		for _, id := range prior {
			if id != "" && id != client.ID {
				crossClient = true
				break
			}
		}
		if h.hooks != nil && (crossClient || prompt == "none") {
			h.hooks.Emit(service.EventSSOSession, map[string]any{
				"user_id": session.UserID, "username": session.Username,
				"session_id": session.ID, "client_id": client.ID,
				"prompt": prompt, "scope": scope,
			})
		}
	}

	if needsIDToken && hasOpenID && h.oidcHandler != nil {
		idToken, err = h.oidcHandler.CreateIDToken(client.ID, session.UserID, nonce, scopes, oidc.IDTokenExtra{SID: session.ID, AuthTime: session.AuthTime})
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token", state)
			return
		}
	}

	// Build response parameters
	params := url.Values{}
	if needsCode {
		params.Set("code", code)
	}
	if needsToken {
		params.Set("access_token", accessToken)
		params.Set("token_type", "Bearer")
		params.Set("expires_in", fmt.Sprintf("%d", int(h.cfg.Security.AccessTokenLifetime.Seconds())))
	}
	if needsIDToken && idToken != "" {
		params.Set("id_token", idToken)
	}
	if state != "" {
		params.Set("state", state)
	}

	// Handle response_mode
	if responseMode == "form_post" {
		// Return HTML form that auto-submits to redirect_uri
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Submit This Form</title></head>
<body onload="javascript:document.forms[0].submit()">
<form method="post" action="%s">`, redirectURI)
		for key, values := range params {
			for _, value := range values {
				_, _ = fmt.Fprintf(w, `<input type="hidden" name="%s" value="%s"/>`, key, value)
			}
		}
		_, _ = fmt.Fprintf(w, `</form></body></html>`)
		return
	}

	// Default: fragment response for implicit/hybrid, query for code
	if responseType == "none" {
		if len(params) > 0 {
			redirectTo := redirectURI
			if strings.Contains(redirectTo, "?") {
				redirectTo += "&" + params.Encode()
			} else {
				redirectTo += "?" + params.Encode()
			}
			http.Redirect(w, r, redirectTo, http.StatusFound)
		}
		return
	}

	if needsCode && !needsToken && !needsIDToken {
		// Code only - use query parameter
		redirectTo := redirectURI
		if strings.Contains(redirectTo, "?") {
			redirectTo += "&" + params.Encode()
		} else {
			redirectTo += "?" + params.Encode()
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	// Implicit/hybrid - use fragment
	redirectTo := redirectURI + "#" + params.Encode()
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (h *Handler) getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil || h.sessions == nil {
		return nil
	}
	stored, err := h.sessions.Get(cookie.Value)
	if err != nil || stored == nil {
		return nil
	}
	return &Session{
		ID:            stored.ID,
		UserID:        stored.UserID,
		Username:      stored.Username,
		Authenticated: true,
		MFAVerified:   stored.MFAVerified,
		AuthTime:      stored.AuthTime,
	}
}

func (h *Handler) GetSession(r *http.Request) *Session {
	return h.getSession(r)
}

func (h *Handler) SetSession(w http.ResponseWriter, userID, username string) {
	h.SetSessionWithMFA(w, userID, username, true)
}

func (h *Handler) SetSessionWithMFA(w http.ResponseWriter, userID, username string, mfaVerified bool) {
	h.SetSessionRequest(w, nil, userID, username, mfaVerified)
}

func (h *Handler) SetSessionRequest(w http.ResponseWriter, r *http.Request, userID, username string, mfaVerified bool) {
	if h.sessions == nil {
		return
	}
	ua, ip := "", ""
	if r != nil {
		ua = r.UserAgent()
		trusted := []string(nil)
		if h.cfg != nil {
			trusted = h.cfg.Security.TrustedProxies
		}
		ip = service.ClientIP(r, trusted)
	}
	sess, err := h.sessions.Start(userID, username, ua, ip, mfaVerified)
	if err != nil {
		return
	}
	h.writeSessionCookie(w, sess.ID)
}

func (h *Handler) MarkSessionMFA(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil || h.sessions == nil {
		return
	}
	_ = h.sessions.MarkMFA(cookie.Value)
	h.writeSessionCookie(w, cookie.Value)
}

func (h *Handler) writeSessionCookie(w http.ResponseWriter, sessionID string) {
	maxAge := int(h.cfg.Security.SessionLifetime.Seconds())
	if maxAge <= 0 {
		maxAge = 8 * 3600
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Server.TLS.Enabled,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (h *Handler) hasConsented(userID, clientID, scope string) bool {
	consent, err := h.consentRepo.Get(userID, clientID)
	if err != nil {
		return false
	}
	requestedScopes := crypto.NormalizeScopes(scope)
	for _, s := range requestedScopes {
		if !containsScope(consent.Scopes, s) {
			return false
		}
	}
	return true
}

func (h *Handler) clearSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return
	}
	if h.logout != nil {
		h.logout.End(cookie.Value)
	} else if h.sessions != nil {
		_ = h.sessions.Revoke(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Server.TLS.Enabled,
		MaxAge:   -1,
	})
}

func (h *Handler) ClearSession(w http.ResponseWriter, r *http.Request) {
	h.clearSession(w, r)
}

func (h *Handler) GetPARParams(requestURI string) (map[string]string, error) {
	par, err := h.parRepo.GetByRequestURI(requestURI)
	if err != nil {
		return nil, err
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(par.RequestParams), &params); err != nil {
		return nil, err
	}
	return params, nil
}

// SaveConsent persists the user's consent for a client
func (h *Handler) SaveConsent(userID, clientID string, scopes []string) error {
	return h.consentRepo.Save(userID, clientID, scopes)
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	// Check for duplicate parameters
	if hasDuplicateParams(r) {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Duplicate parameters are not allowed")
		return
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeToken(w, r)
	case "client_credentials":
		h.handleClientCredentialsToken(w, r)
	case "refresh_token":
		h.handleRefreshToken(w, r)
	case "password":
		h.handlePasswordToken(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.HandleDeviceToken(w, r)
	case "urn:openid:params:grant-type:ciba":
		h.HandleCIBAToken(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		h.handleTokenExchange(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type: "+grantType)
	}
}

func (h *Handler) handleAuthorizationCodeToken(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	codeVerifier := r.Form.Get("code_verifier")

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if code == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	authCode, err := h.authCodeRepo.Get(code)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")
		return
	}

	client, ok := h.requireClient(w, authCode.ClientID, "", http.StatusBadRequest)
	if !ok {
		return
	}

	// Validate mTLS only when client auth method requires it
	if client.TokenEndpointAuthMethod == "tls_client_auth" || client.TokenEndpointAuthMethod == "self_signed_tls_client_auth" {
		cert := h.mtlsSvc.ExtractClientCertificate(r)
		if cert == nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client certificate required")
			return
		}
		if err := h.mtlsSvc.ValidateClientCertificate(cert, nil); err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Invalid client certificate: "+err.Error())
			return
		}
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}

	if authCode.Used {
		if authCode.FamilyID != "" {
			_ = h.tokenRepo.RevokeFamily(authCode.FamilyID)
		} else {
			_ = h.tokenRepo.RevokeAllForClient(authCode.ClientID, authCode.UserID)
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code already used")
		return
	}

	if time.Now().After(authCode.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code expired")
		return
	}

	// RFC 6749: redirect_uri is REQUIRED if included in authorization request
	if redirectURI != authCode.RedirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	if client.TokenEndpointAuthMethod != "none" {
		if clientID != client.ID {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "client_id mismatch")
			return
		}
		if clientSecret != client.Secret {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Invalid client secret")
			return
		}
	}

	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
			return
		}
		if !crypto.ValidateCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid code_verifier")
			return
		}
	}

	if err := h.authCodeRepo.MarkUsed(code); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to mark authorization code as used")
		return
	}

	tokenType := boundTokenType(client)

	accessToken, err := h.issueAccessToken(authCode.ClientID, authCode.UserID, strings.Join(authCode.Scopes, " "), tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  authCode.ClientID,
		UserID:    authCode.UserID,
		Scopes:    authCode.Scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    authCode.ClientID,
		UserID:      authCode.UserID,
		Scopes:      authCode.Scopes,
		FamilyID:    authCode.FamilyID,
		ExpiresAt:   time.Now().Add(h.cfg.Security.RefreshTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(refreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	var idToken string
	if containsScope(authCode.Scopes, "openid") && h.oidcHandler != nil {
		// Use nonce stored with the authorization code, not from the token request
		idToken, err = h.oidcHandler.CreateIDToken(authCode.ClientID, authCode.UserID, authCode.Nonce, authCode.Scopes, oidc.IDTokenExtra{SID: authCode.SessionID, AuthTime: authCode.AuthTime})
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token")
			return
		}
	}

	writeOIDCTokenResponse(w, accessToken, refreshToken, idToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(authCode.Scopes, " "))
}

func (h *Handler) handleClientCredentialsToken(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if clientID == "" || clientSecret == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client credentials required")
		return
	}

	client, ok := h.requireClient(w, clientID, "", http.StatusUnauthorized)
	if !ok {
		return
	}

	if client.Secret != clientSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client secret")
		return
	}

	// Validate mTLS only when client auth method requires it
	if client.TokenEndpointAuthMethod == "tls_client_auth" || client.TokenEndpointAuthMethod == "self_signed_tls_client_auth" {
		cert := h.mtlsSvc.ExtractClientCertificate(r)
		if cert == nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client certificate required")
			return
		}
		if err := h.mtlsSvc.ValidateClientCertificate(cert, nil); err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Invalid client certificate: "+err.Error())
			return
		}
	}

	hasGrantType := false
	for _, gt := range client.GrantTypes {
		if gt == "client_credentials" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client not authorized for client_credentials grant")
		return
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}

	scopes, err := service.AllowedScopes(r.Form.Get("scope"), client.Scopes)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}

	tokenType := boundTokenType(client)

	accessToken, err := h.issueAccessToken(clientID, "", strings.Join(scopes, " "), tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scopes:    scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token: "+err.Error())
		return
	}

	writeTokenResponse(w, accessToken, "", int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(scopes, " "))
}

func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenStr := r.Form.Get("refresh_token")
	if refreshTokenStr == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	refreshToken, err := h.tokenRepo.GetRefreshToken(refreshTokenStr)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
		return
	}

	// Refresh token reuse detection - revoke entire grant family
	if refreshToken.Revoked {
		if refreshToken.FamilyID != "" {
			_ = h.tokenRepo.RevokeFamily(refreshToken.FamilyID)
		} else {
			_ = h.tokenRepo.RevokeAllForClient(refreshToken.ClientID, refreshToken.UserID)
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token revoked")
		return
	}

	if !refreshToken.ExpiresAt.IsZero() && time.Now().After(refreshToken.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token expired")
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	client, ok := h.requireClient(w, refreshToken.ClientID, "", http.StatusBadRequest)
	if !ok {
		return
	}

	if client.TokenEndpointAuthMethod != "none" {
		if clientID != client.ID || clientSecret != client.Secret {
			writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
			return
		}
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	tokenType := boundTokenType(client)

	newAccessToken, err := h.issueAccessToken(refreshToken.ClientID, refreshToken.UserID, strings.Join(refreshToken.Scopes, " "), tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	newRefreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	_ = h.tokenRepo.RevokeAccessToken(refreshToken.AccessToken)
	_ = h.tokenRepo.RevokeRefreshToken(refreshTokenStr)

	accessTok := &models.AccessToken{
		Token:     newAccessToken,
		ClientID:  refreshToken.ClientID,
		UserID:    refreshToken.UserID,
		Scopes:    refreshToken.Scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	familyID := refreshToken.FamilyID
	if familyID == "" {
		familyID = uuid.New().String()
	}
	newRefreshTok := &models.RefreshToken{
		Token:       newRefreshToken,
		AccessToken: newAccessToken,
		ClientID:    refreshToken.ClientID,
		UserID:      refreshToken.UserID,
		Scopes:      refreshToken.Scopes,
		FamilyID:    familyID,
		ExpiresAt:   time.Now().Add(h.cfg.Security.RefreshTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(newRefreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	writeTokenResponse(w, newAccessToken, newRefreshToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(refreshToken.Scopes, " "))
}

func (h *Handler) handlePasswordToken(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if clientID == "" || clientSecret == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client credentials required")
		return
	}

	client, ok := h.requireClient(w, clientID, "", http.StatusUnauthorized)
	if !ok {
		return
	}

	if client.Secret != clientSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client secret")
		return
	}

	hasGrantType := false
	for _, gt := range client.GrantTypes {
		if gt == "password" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client not authorized for password grant")
		return
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	tokenType := boundTokenType(client)

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username == "" || password == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}

	if h.userSvc == nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Password hasher is not configured")
		return
	}

	user, err := h.userSvc.Authenticate(username, password)
	if err != nil {
		if existing, lookupErr := h.userRepo.GetByUsername(username); lookupErr == nil && h.logins != nil {
			h.logins.Record(existing, r, false, false)
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid username or password")
		return
	}
	if h.logins != nil {
		h.logins.Record(user, r, true, false)
	}

	scope := r.Form.Get("scope")
	scopes := crypto.NormalizeScopes(scope)
	if len(scopes) == 0 {
		scopes = client.Scopes
	}

	accessToken, err := h.issueAccessToken(clientID, user.ID, strings.Join(scopes, " "), tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    user.ID,
		Scopes:    scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    clientID,
		UserID:      user.ID,
		Scopes:      scopes,
		FamilyID:    uuid.New().String(),
		ExpiresAt:   time.Now().Add(h.cfg.Security.RefreshTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(refreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	var idToken string
	if containsScope(scopes, "openid") && h.oidcHandler != nil {
		idToken, err = h.oidcHandler.CreateIDToken(clientID, user.ID, "", scopes)
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token")
			return
		}
	}

	writeOIDCTokenResponse(w, accessToken, refreshToken, idToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(scopes, " "))
}

func (h *Handler) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client authentication required")
		return
	}

	client, ok := h.requireClient(w, clientID, "", http.StatusUnauthorized)
	if !ok {
		return
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	tokenType := boundTokenType(client)

	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")

	if subjectToken == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}

	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Unsupported subject_token_type: "+subjectTokenType)
		return
	}

	subjectTokenInfo, err := h.tokenRepo.GetAccessToken(subjectToken)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid subject_token")
		return
	}

	if subjectTokenInfo.Revoked || time.Now().After(subjectTokenInfo.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token is expired or revoked")
		return
	}

	scope := r.Form.Get("scope")
	scopes := crypto.NormalizeScopes(scope)
	if len(scopes) == 0 {
		scopes = subjectTokenInfo.Scopes
	}

	accessToken, err := h.issueAccessToken(clientID, subjectTokenInfo.UserID, strings.Join(scopes, " "), tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    subjectTokenInfo.UserID,
		Scopes:    scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":      accessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        tokenType,
		"expires_in":        int(h.cfg.Security.AccessTokenLifetime.Seconds()),
		"scope":             strings.Join(scopes, " "),
	})
}

func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	token := r.Form.Get("token")
	tokenTypeHint := r.Form.Get("token_type_hint")

	if token == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	// Require client authentication
	if clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client authentication required")
		return
	}

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found")
		return
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	if !h.revokeDPoP(w, r, client, token) {
		return
	}

	switch tokenTypeHint {
	case "refresh_token":
		if rt, err := h.tokenRepo.GetRefreshToken(token); err == nil {
			// Validate client binding
			if rt.ClientID != clientID {
				writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token does not belong to this client")
				return
			}
			_ = h.tokenRepo.RevokeRefreshToken(token)
			if rt.AccessToken != "" {
				_ = h.tokenRepo.RevokeAccessToken(rt.AccessToken)
			}
		}
	case "access_token":
		if at, err := h.tokenRepo.GetAccessToken(token); err == nil {
			// Validate client binding
			if at.ClientID != clientID {
				writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token does not belong to this client")
				return
			}
			_ = h.tokenRepo.RevokeAccessToken(token)
			// Cascade: also revoke associated refresh token
			if rt, err := h.tokenRepo.GetRefreshTokenByAccessToken(token); err == nil {
				_ = h.tokenRepo.RevokeRefreshToken(rt.Token)
			}
		}
	default:
		if rt, err := h.tokenRepo.GetRefreshToken(token); err == nil {
			if rt.ClientID != clientID {
				writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token does not belong to this client")
				return
			}
			_ = h.tokenRepo.RevokeRefreshToken(token)
			if rt.AccessToken != "" {
				_ = h.tokenRepo.RevokeAccessToken(rt.AccessToken)
			}
		} else if at, err := h.tokenRepo.GetAccessToken(token); err == nil {
			if at.ClientID != clientID {
				writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token does not belong to this client")
				return
			}
			_ = h.tokenRepo.RevokeAccessToken(token)
			// Cascade: also revoke associated refresh token
			if rt, err := h.tokenRepo.GetRefreshTokenByAccessToken(token); err == nil {
				_ = h.tokenRepo.RevokeRefreshToken(rt.Token)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}
	client, err := h.clientRepo.GetByID(clientID)
	if err != nil || client == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	result, err := h.introspect.Introspect(client, r.Form.Get("token"), r.Form.Get("token_type_hint"))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if result != nil && result.Active && result.Sub != "" && h.oidcHandler != nil {
		computed, err := h.oidcHandler.SubjectFor(result.ClientID, result.Sub)
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to resolve subject")
			return
		}
		result.Sub = computed
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if h.cfg != nil && !h.cfg.Registration.DCREnabled {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "registration_disabled",
			"error_description": "Dynamic client registration is disabled",
		})
		return
	}

	var req struct {
		RedirectURIs                          []string `json:"redirect_uris"`
		TokenEndpointAuthMethod               string   `json:"token_endpoint_auth_method"`
		GrantTypes                            []string `json:"grant_types"`
		ResponseTypes                         []string `json:"response_types"`
		ClientName                            string   `json:"client_name"`
		Scope                                 string   `json:"scope"`
		DPoPBoundAccessTokens                 bool     `json:"dpop_bound_access_tokens"`
		RequirePushedAuthorizationRequests    bool     `json:"require_pushed_authorization_requests"`
		BackchannelTokenDeliveryMode          string   `json:"backchannel_token_delivery_mode"`
		BackchannelClientNotificationEndpoint string   `json:"backchannel_client_notification_endpoint"`
		BackchannelLogoutURI                  string   `json:"backchannel_logout_uri"`
		BackchannelLogoutSessionRequired      *bool    `json:"backchannel_logout_session_required"`
		PostLogoutRedirectURIs                []string `json:"post_logout_redirect_uris"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid request body"})
		return
	}

	if req.ClientName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "client_name is required"})
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "redirect_uris is required"})
		return
	}

	for _, uri := range req.RedirectURIs {
		if !isValidURI(uri) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "Invalid redirect URI: " + uri})
			return
		}
	}

	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}

	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}

	client := &models.Client{
		ID:                                    uuid.New().String(),
		Secret:                                mustGenerateToken(),
		Name:                                  req.ClientName,
		RedirectURIs:                          req.RedirectURIs,
		GrantTypes:                            req.GrantTypes,
		Scopes:                                service.StripManagement(strings.Fields(req.Scope)),
		TokenEndpointAuthMethod:               req.TokenEndpointAuthMethod,
		DPoPBoundAccessTokens:                 req.DPoPBoundAccessTokens,
		RequirePushedAuthorizationRequests:    req.RequirePushedAuthorizationRequests,
		BackchannelTokenDeliveryMode:          req.BackchannelTokenDeliveryMode,
		BackchannelClientNotificationEndpoint: req.BackchannelClientNotificationEndpoint,
		BackchannelLogoutURI:                  req.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:      req.BackchannelLogoutSessionRequired == nil || *req.BackchannelLogoutSessionRequired,
		PostLogoutRedirectURIs:                req.PostLogoutRedirectURIs,
		RegistrationSource:                    "dcr",
		DCREnabled:                            true,
		CreatedAt:                             time.Now(),
		UpdatedAt:                             time.Now(),
	}

	if err := h.clientRepo.Create(client); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to create client"})
		return
	}
	if h.audit != nil {
		h.audit.Write("client", client.ID, "client.register", "client", client.ID, r, map[string]any{"name": client.Name, "source": "dcr"})
	}

	response := map[string]interface{}{
		"client_id":                  client.ID,
		"client_secret":              client.Secret,
		"client_id_issued_at":        client.CreatedAt.Unix(),
		"client_secret_expires_at":   0,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"response_types":             req.ResponseTypes,
		"client_name":                client.Name,
		"scope":                      strings.Join(client.Scopes, " "),
	}

	writeJSON(w, http.StatusCreated, response)
}

func (h *Handler) AuthenticateClient(r *http.Request) (*models.Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found")
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

func isValidRedirectURI(uri string, allowedURIs []string) bool {
	if len(allowedURIs) == 0 {
		return isValidURI(uri)
	}
	for _, allowed := range allowedURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

func isValidURI(uri string) bool {
	return strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://localhost")
}

func (h *Handler) issueAccessToken(clientID, userID, scope, tokenType string) (string, error) {
	format := ""
	var lifetime time.Duration
	if h.cfg != nil {
		format = h.cfg.Security.AccessTokenFormat
		lifetime = h.cfg.Security.AccessTokenLifetime
	}
	if format == "jwt" {
		if h.oidcHandler == nil {
			return "", fmt.Errorf("jwt access tokens require the oidc handler")
		}
		return h.oidcHandler.CreateAccessTokenJWT(clientID, userID, scope, tokenType, lifetime)
	}
	return crypto.GenerateToken()
}

func mustGenerateToken() string {
	token, err := crypto.GenerateToken()
	if err != nil {
		return uuid.New().String()
	}
	return token
}

func hasDuplicateParams(r *http.Request) bool {
	// Check URL query parameters
	urlValues := r.URL.Query()
	for key := range urlValues {
		if len(urlValues[key]) > 1 {
			return true
		}
	}

	// Check form parameters (POST body)
	if r.Form != nil {
		for key := range r.Form {
			if len(r.Form[key]) > 1 {
				return true
			}
		}
	}

	return false
}

func writeOAuthError(w http.ResponseWriter, status int, code, description, state string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	response := map[string]string{
		"error":             code,
		"error_description": description,
	}
	if state != "" {
		response["state"] = state
	}
	_ = json.NewEncoder(w).Encode(response)
}

func writeTokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeTokenResponse(w http.ResponseWriter, accessToken, refreshToken string, expiresIn int, tokenType, scope string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}

	if refreshToken != "" {
		response["refresh_token"] = refreshToken
	}

	if scope != "" {
		response["scope"] = scope
	}

	_ = json.NewEncoder(w).Encode(response)
}

func writeOIDCTokenResponse(w http.ResponseWriter, accessToken, refreshToken, idToken string, expiresIn int, tokenType, scope string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}

	if refreshToken != "" {
		response["refresh_token"] = refreshToken
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	if scope != "" {
		response["scope"] = scope
	}

	_ = json.NewEncoder(w).Encode(response)
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
