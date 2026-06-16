package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func (h *Handler) HandleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Failed to parse request",
		})
		return
	}

	// Check for duplicate parameters
	if hasDuplicateParams(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Duplicate parameters are not allowed",
		})
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_client",
			"error_description": "Client not found",
		})
		return
	}

	if client.TokenEndpointAuthMethod != "none" && client.Secret != clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	hasGrantType := false
	for _, gt := range client.GrantTypes {
		if gt == "urn:ietf:params:oauth:grant-type:device_code" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unauthorized_client",
			"error_description": "Client not authorized for device_code grant",
		})
		return
	}

	scope := r.Form.Get("scope")
	scopes := crypto.NormalizeScopes(scope)

	deviceCode, err := crypto.GenerateDeviceCode()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to generate device code",
		})
		return
	}

	userCode, err := crypto.GenerateUserCode()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to generate user code",
		})
		return
	}

	interval := 5
	expiresIn := int(h.cfg.Security.DeviceCodeLifetime.Seconds())

	dc := &models.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		Status:     "pending",
		ExpiresAt:  time.Now().Add(h.cfg.Security.DeviceCodeLifetime),
		Interval:   interval,
	}

	if err := h.deviceRepo.Save(dc); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to save device code",
		})
		return
	}

	issuer := h.cfg.Security.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", h.cfg.Server.Port)
	}

	queueReq := &queue.AuthRequest{
		ID:             deviceCode,
		Type:           queue.AuthRequestTypeDevice,
		ClientID:       clientID,
		UserCode:       userCode,
		BindingMessage: fmt.Sprintf("Enter code: %s", userCode),
		Status:         queue.StatusPending,
		Interval:       interval,
		CreatedAt:      time.Now(),
		ExpiresAt:      dc.ExpiresAt,
	}

	if err := h.q.Enqueue(queueReq); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to enqueue device code request",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          issuer + "/device",
		"verification_uri_complete": issuer + "/device?user_code=" + userCode,
		"expires_in":                expiresIn,
		"interval":                  interval,
	})
}

func (h *Handler) HandleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	deviceCode := r.Form.Get("device_code")
	if deviceCode == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	dc, err := h.deviceRepo.GetByDeviceCode(deviceCode)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid device code")
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "Device code expired")
		return
	}

	client, err := h.clientRepo.GetByID(dc.ClientID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client not found")
		return
	}

	if client.TokenEndpointAuthMethod != "none" {
		if clientID != dc.ClientID || clientSecret != client.Secret {
			writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
			return
		}
	}

	switch dc.Status {
	case "pending":
		writeTokenError(w, http.StatusBadRequest, "authorization_pending", "User has not yet approved the request")
		return
	case "denied":
		writeTokenError(w, http.StatusBadRequest, "access_denied", "User denied the request")
		return
	case "expired":
		writeTokenError(w, http.StatusBadRequest, "expired_token", "Device code expired")
		return
	}

	if dc.Status != "approved" {
		writeTokenError(w, http.StatusBadRequest, "authorization_pending", "Request is still pending")
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

	var userID string
	queueReq, err := h.q.GetByID(deviceCode)
	if err == nil && queueReq.UserID != "" {
		userID = queueReq.UserID
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  dc.ClientID,
		UserID:    userID,
		Scopes:    dc.Scopes,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    dc.ClientID,
		UserID:      userID,
		Scopes:      dc.Scopes,
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

	writeTokenResponse(w, accessToken, refreshToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), "Bearer", strings.Join(dc.Scopes, " "))
}

func (h *Handler) HandleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Device Authorization</title></head>
<body>
<h1>Device Authorization</h1>
<form method="POST" action="/device">
	<label for="user_code">Enter the code shown on your device:</label><br>
	<input type="text" id="user_code" name="user_code" required><br><br>
	<button type="submit">Submit</button>
</form>
</body>
</html>`)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
		return
	}

	userCode := r.Form.Get("user_code")
	if userCode == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "user_code is required",
		})
		return
	}

	dc, err := h.deviceRepo.GetByUserCode(userCode)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": "Invalid user code",
		})
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "expired_token",
			"error_description": "User code expired",
		})
		return
	}

	userID := r.Form.Get("user_id")

	if err := h.deviceRepo.UpdateStatus(dc.DeviceCode, "approved"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to update device code",
		})
		return
	}

	_ = h.q.Approve(dc.DeviceCode, userID)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Authorization Approved</title></head>
<body>
<h1>Authorization Approved</h1>
<p>You have successfully authorized the device.</p>
<p>You can now return to your device.</p>
</body>
</html>`)
}
