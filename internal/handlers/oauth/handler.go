package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

type Handler struct {
	db          *database.DB
	cfg         *config.Config
	q           *queue.MemoryQueue
	oidcHandler *oidc.Handler
	sessions    map[string]*Session
}

type Session struct {
	UserID        string
	Username      string
	Authenticated bool
	MFAVerified   bool
}

func NewHandler(db *database.DB, cfg *config.Config, q *queue.MemoryQueue, oidcHandler *oidc.Handler) *Handler {
	return &Handler{
		db:          db,
		cfg:         cfg,
		q:           q,
		oidcHandler: oidcHandler,
		sessions:    make(map[string]*Session),
	}
}

var validResponseTypes = map[string]bool{
	"code":                true,
	"token":               true,
	"id_token":            true,
	"code id_token":       true,
	"code token":          true,
	"code id_token token": true,
	"none":                true,
}

func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	prompt := r.URL.Query().Get("prompt")

	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required", "")
		return
	}

	client, err := h.db.GetClient(clientID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "Client not found", "")
		return
	}

	if !validResponseTypes[responseType] {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "Unsupported response_type: "+responseType, state)
		return
	}

	if redirectURI == "" && len(client.RedirectURIs) > 0 {
		redirectURI = client.RedirectURIs[0]
	}

	if !isValidRedirectURI(redirectURI, client.RedirectURIs) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri", state)
		return
	}

	needsCode := strings.Contains(responseType, "code")
	if needsCode && h.cfg.Security.RequirePKCE && codeChallenge == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge is required", state)
		return
	}

	if codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Unsupported code_challenge_method", state)
			return
		}
		if codeChallengeMethod == "plain" && !h.cfg.Security.AllowPlainPKCE {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "plain code_challenge_method is not allowed", state)
			return
		}
	}

	session := h.getSession(r)

	if session == nil || !session.Authenticated {
		loginURL := "/login?" + r.URL.RawQuery
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	if !session.MFAVerified && h.cfg.Security.MFA.Required {
		mfaURL := "/login/mfa?" + r.URL.RawQuery
		http.Redirect(w, r, mfaURL, http.StatusFound)
		return
	}

	if prompt == "consent" || !h.hasConsented(session.UserID, clientID, scope) {
		consentURL := "/consent?" + r.URL.RawQuery
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	h.issueAuthorizationResponse(w, r, client, session, responseType, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod)
}

func (h *Handler) issueAuthorizationResponse(w http.ResponseWriter, r *http.Request, client *models.Client, session *Session, responseType, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) {
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
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ExpiresAt:           time.Now().Add(h.cfg.Security.AuthorizationCodeLifetime),
			Used:                false,
		}

		if err := h.db.SaveAuthorizationCode(authCode); err != nil {
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
			TokenType: "Bearer",
			ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
		}

		if err := h.db.SaveAccessToken(accessTok); err != nil {
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

	if responseType == "none" {
		params := url.Values{}
		if state != "" {
			params.Set("state", state)
		}
		redirectTo := redirectURI
		if len(params) > 0 {
			if strings.Contains(redirectTo, "?") {
				redirectTo += "&" + params.Encode()
			} else {
				redirectTo += "?" + params.Encode()
			}
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	if needsCode && !needsToken && !needsIDToken {
		params := url.Values{}
		params.Set("code", code)
		if state != "" {
			params.Set("state", state)
		}
		redirectTo := redirectURI
		if strings.Contains(redirectTo, "?") {
			redirectTo += "&" + params.Encode()
		} else {
			redirectTo += "?" + params.Encode()
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	fragment := url.Values{}
	if needsCode {
		fragment.Set("code", code)
	}
	if needsToken {
		fragment.Set("access_token", accessToken)
		fragment.Set("token_type", "Bearer")
		fragment.Set("expires_in", fmt.Sprintf("%d", int(h.cfg.Security.AccessTokenLifetime.Seconds())))
	}
	if needsIDToken && idToken != "" {
		fragment.Set("id_token", idToken)
	}
	if state != "" {
		fragment.Set("state", state)
	}

	redirectTo := redirectURI + "#" + fragment.Encode()
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (h *Handler) getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}
	session, exists := h.sessions[cookie.Value]
	if !exists {
		return nil
	}
	return session
}

func (h *Handler) SetSession(w http.ResponseWriter, userID, username string) {
	sessionID := uuid.New().String()
	h.sessions[sessionID] = &Session{
		UserID:        userID,
		Username:      username,
		Authenticated: true,
		MFAVerified:   true,
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})
}

func (h *Handler) hasConsented(userID, clientID, scope string) bool {
	return true
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
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
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.HandleDeviceToken(w, r)
	case "urn:openid:params:grant-type:ciba":
		h.HandleCIBAToken(w, r)
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

	authCode, err := h.db.GetAuthorizationCode(code)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")
		return
	}

	if authCode.Used {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code already used")
		return
	}

	if time.Now().After(authCode.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code expired")
		return
	}

	if redirectURI != "" && redirectURI != authCode.RedirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	client, err := h.db.GetClient(authCode.ClientID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client not found")
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

	if err := h.db.UseAuthorizationCode(code); err != nil {
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

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  authCode.ClientID,
		UserID:    authCode.UserID,
		Scopes:    authCode.Scopes,
		TokenType: "Bearer",
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

	if err := h.db.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.db.SaveRefreshToken(refreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	var idToken string
	if containsScope(authCode.Scopes, "openid") && h.oidcHandler != nil {
		nonce := r.Form.Get("nonce")
		idToken, err = h.oidcHandler.CreateIDToken(authCode.ClientID, authCode.UserID, nonce, authCode.Scopes)
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token")
			return
		}
	}

	writeOIDCTokenResponse(w, accessToken, refreshToken, idToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), "Bearer", strings.Join(authCode.Scopes, " "))
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

	client, err := h.db.GetClient(clientID)
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
		if gt == "client_credentials" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client not authorized for client_credentials grant")
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

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scopes:    scopes,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	if err := h.db.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token: "+err.Error())
		return
	}

	writeTokenResponse(w, accessToken, "", int(h.cfg.Security.AccessTokenLifetime.Seconds()), "Bearer", strings.Join(scopes, " "))
}

func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenStr := r.Form.Get("refresh_token")
	if refreshTokenStr == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	refreshToken, err := h.db.GetRefreshToken(refreshTokenStr)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
		return
	}

	if refreshToken.Revoked {
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

	client, err := h.db.GetClient(refreshToken.ClientID)
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

	// Revoke old tokens (best effort, ignore errors)
	_ = h.db.RevokeAccessToken(refreshToken.AccessToken)
	_ = h.db.RevokeRefreshToken(refreshTokenStr)

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

	if err := h.db.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.db.SaveRefreshToken(newRefreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	writeTokenResponse(w, newAccessToken, newRefreshToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), "Bearer", strings.Join(refreshToken.Scopes, " "))
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

	client, err := h.db.GetClient(clientID)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch tokenTypeHint {
	case "refresh_token":
		if rt, err := h.db.GetRefreshToken(token); err == nil && rt.ClientID == clientID {
			_ = h.db.RevokeRefreshToken(token)
			if rt.AccessToken != "" {
				_ = h.db.RevokeAccessToken(rt.AccessToken)
			}
		}
	case "access_token":
		if at, err := h.db.GetAccessToken(token); err == nil && at.ClientID == clientID {
			_ = h.db.RevokeAccessToken(token)
		}
	default:
		if rt, err := h.db.GetRefreshToken(token); err == nil && rt.ClientID == clientID {
			_ = h.db.RevokeRefreshToken(token)
			if rt.AccessToken != "" {
				_ = h.db.RevokeAccessToken(rt.AccessToken)
			}
		} else if at, err := h.db.GetAccessToken(token); err == nil && at.ClientID == clientID {
			_ = h.db.RevokeAccessToken(token)
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

	client, err := h.db.GetClient(clientID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	at, err := h.db.GetAccessToken(token)
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
		if user, err := h.db.GetUser(at.UserID); err == nil {
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
		Secret:                                uuid.New().String(),
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

	if err := h.db.CreateClient(client); err != nil {
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

	client, err := h.db.GetClient(clientID)
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
