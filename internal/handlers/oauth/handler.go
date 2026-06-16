package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

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
	q            *queue.MemoryQueue
	oidcHandler  *oidc.Handler
	sessions     map[string]*Session
	mu           sync.RWMutex
}

type Session struct {
	UserID        string
	Username      string
	Authenticated bool
	MFAVerified   bool
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
	q *queue.MemoryQueue,
	oidcHandler *oidc.Handler,
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
		sessions:     make(map[string]*Session),
	}
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
			client, err := h.clientRepo.GetByID(clientID)
			if err == nil && h.jarSvc != nil {
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

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "Client not found", "")
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
			ExpiresAt:           time.Now().Add(h.cfg.Security.AuthorizationCodeLifetime),
			Used:                false,
		}

		if err := h.authCodeRepo.Save(authCode); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to save authorization code", state)
			return
		}
	}

	if needsToken {
		accessToken, err = crypto.GenerateToken()
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

	if needsIDToken && hasOpenID && h.oidcHandler != nil {
		idToken, err = h.oidcHandler.CreateIDToken(client.ID, session.UserID, nonce, scopes)
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
	if err != nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	session, exists := h.sessions[cookie.Value]
	if !exists {
		return nil
	}
	return session
}

func (h *Handler) GetSession(r *http.Request) *Session {
	return h.getSession(r)
}

func (h *Handler) SetSession(w http.ResponseWriter, userID, username string) {
	h.SetSessionWithMFA(w, userID, username, true)
}

func (h *Handler) SetSessionWithMFA(w http.ResponseWriter, userID, username string, mfaVerified bool) {
	sessionID := uuid.New().String()
	h.mu.Lock()
	h.sessions[sessionID] = &Session{
		UserID:        userID,
		Username:      username,
		Authenticated: true,
		MFAVerified:   mfaVerified,
	}
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Server.TLS.Enabled,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
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
	h.mu.Lock()
	delete(h.sessions, cookie.Value)
	h.mu.Unlock()

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

	// Get client to check DPoP requirement
	client, err := h.clientRepo.GetByID(authCode.ClientID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client not found")
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

	// Validate DPoP if required
	var dpopJKT string
	if client.DPoPBoundAccessTokens {
		dpopHeader := r.Header.Get("DPoP")
		if dpopHeader == "" {
			writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", "DPoP header required")
			return
		}
		if err := h.ValidateDPoPProof(r, ""); err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
			return
		}
		dpopJKT, err = h.GetDPoPJKT(r)
		if err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", "Failed to get JKT")
			return
		}
	}

	if authCode.Used {
		// RFC 6749: Revoke all tokens issued from this code on reuse
		_ = h.tokenRepo.RevokeAllForClient(authCode.ClientID, authCode.UserID)
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

	accessToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	tokenType := "Bearer"
	if client.DPoPBoundAccessTokens {
		tokenType = "DPoP"
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
		idToken, err = h.oidcHandler.CreateIDToken(authCode.ClientID, authCode.UserID, authCode.Nonce, authCode.Scopes)
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

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found")
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

	// Validate DPoP if required
	var dpopJKT string
	if client.DPoPBoundAccessTokens {
		dpopHeader := r.Header.Get("DPoP")
		if dpopHeader == "" {
			writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", "DPoP header required")
			return
		}
		if err := h.ValidateDPoPProof(r, ""); err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
			return
		}
		dpopJKT, err = h.GetDPoPJKT(r)
		if err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", "Failed to get JKT")
			return
		}
	}

	scope := r.Form.Get("scope")
	scopes := crypto.NormalizeScopes(scope)
	if len(scopes) == 0 {
		scopes = client.Scopes
	}

	accessToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	tokenType := "Bearer"
	if client.DPoPBoundAccessTokens {
		tokenType = "DPoP"
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
		// Revoke all tokens for this client/user combination
		_ = h.tokenRepo.RevokeAllForClient(refreshToken.ClientID, refreshToken.UserID)
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

	client, err := h.clientRepo.GetByID(refreshToken.ClientID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client not found")
		return
	}

	if client.TokenEndpointAuthMethod != "none" {
		if clientID != client.ID || clientSecret != client.Secret {
			writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
			return
		}
	}

	newAccessToken, err := crypto.GenerateToken()
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
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	newRefreshTok := &models.RefreshToken{
		Token:       newRefreshToken,
		AccessToken: newAccessToken,
		ClientID:    refreshToken.ClientID,
		UserID:      refreshToken.UserID,
		Scopes:      refreshToken.Scopes,
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

	writeTokenResponse(w, newAccessToken, newRefreshToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), "Bearer", strings.Join(refreshToken.Scopes, " "))
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

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found")
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

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username == "" || password == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}

	user, err := h.userRepo.GetByUsername(username)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid username or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid username or password")
		return
	}

	scope := r.Form.Get("scope")
	scopes := crypto.NormalizeScopes(scope)
	if len(scopes) == 0 {
		scopes = client.Scopes
	}

	accessToken, err := crypto.GenerateToken()
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
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    clientID,
		UserID:      user.ID,
		Scopes:      scopes,
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

	writeOIDCTokenResponse(w, accessToken, refreshToken, idToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), "Bearer", strings.Join(scopes, " "))
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

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found")
		return
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

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

	accessToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    subjectTokenInfo.UserID,
		Scopes:    scopes,
		TokenType: "Bearer",
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
		"token_type":        "Bearer",
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

	token := r.Form.Get("token")
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	at, err := h.tokenRepo.GetAccessToken(token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	if at.Revoked || time.Now().After(at.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	response := map[string]interface{}{
		"active":     true,
		"scope":      strings.Join(at.Scopes, " "),
		"client_id":  at.ClientID,
		"token_type": at.TokenType,
		"exp":        at.ExpiresAt.Unix(),
		"iat":        at.ExpiresAt.Add(-h.cfg.Security.AccessTokenLifetime).Unix(),
	}

	if at.UserID != "" {
		response["sub"] = at.UserID
		if user, err := h.userRepo.GetByID(at.UserID); err == nil {
			response["username"] = user.Username
		}
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
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
		Scopes:                                strings.Fields(req.Scope),
		TokenEndpointAuthMethod:               req.TokenEndpointAuthMethod,
		DPoPBoundAccessTokens:                 req.DPoPBoundAccessTokens,
		RequirePushedAuthorizationRequests:    req.RequirePushedAuthorizationRequests,
		BackchannelTokenDeliveryMode:          req.BackchannelTokenDeliveryMode,
		BackchannelClientNotificationEndpoint: req.BackchannelClientNotificationEndpoint,
		CreatedAt:                             time.Now(),
		UpdatedAt:                             time.Now(),
	}

	if err := h.clientRepo.Create(client); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to create client"})
		return
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
