package oauth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func (h *Handler) HandleCIBA(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Failed to parse request",
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

	client, err := h.db.GetClient(clientID)
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
		if gt == "urn:openid:params:grant-type:ciba" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unauthorized_client",
			"error_description": "Client not authorized for CIBA grant",
		})
		return
	}

	scope := r.Form.Get("scope")
	if !strings.Contains(scope, "openid") {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "scope must include 'openid'",
		})
		return
	}

	loginHint := r.Form.Get("login_hint")
	idTokenHint := r.Form.Get("id_token_hint")
	loginHintToken := r.Form.Get("login_hint_token")

	if loginHint == "" && idTokenHint == "" && loginHintToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "One of login_hint, id_token_hint, or login_hint_token is required",
		})
		return
	}

	bindingMessage := r.Form.Get("binding_message")
	userCode := r.Form.Get("user_code")
	clientNotificationToken := r.Form.Get("client_notification_token")

	if client.BackchannelTokenDeliveryMode == "ping" || client.BackchannelTokenDeliveryMode == "push" {
		if clientNotificationToken == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "client_notification_token is required for ping/push mode",
			})
			return
		}
	}

	var userID string
	if loginHint != "" {
		user, err := h.db.GetUserByUsername(loginHint)
		if err == nil {
			userID = user.ID
		}
	}

	authReqID, err := crypto.GenerateAuthReqID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to generate auth_req_id",
		})
		return
	}

	interval := 5
	expiresIn := int(h.cfg.Security.CIBARequestLifetime.Seconds())

	cibaReq := &models.CIBARequest{
		AuthReqID:               authReqID,
		ClientID:                clientID,
		UserID:                  userID,
		BindingMessage:          bindingMessage,
		UserCode:                userCode,
		Status:                  "pending",
		DeliveryMode:            client.BackchannelTokenDeliveryMode,
		ExpiresAt:               time.Now().Add(h.cfg.Security.CIBARequestLifetime),
		Interval:                interval,
		ClientNotificationToken: clientNotificationToken,
	}

	if err := h.db.SaveCIBARequest(cibaReq); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to save CIBA request",
		})
		return
	}

	queueReq := &queue.AuthRequest{
		ID:                      authReqID,
		Type:                    queue.AuthRequestTypeCIBA,
		ClientID:                clientID,
		UserID:                  userID,
		BindingMessage:          bindingMessage,
		UserCode:                userCode,
		Status:                  queue.StatusPending,
		DeliveryMode:            client.BackchannelTokenDeliveryMode,
		Interval:                interval,
		ClientNotificationToken: clientNotificationToken,
		CreatedAt:               time.Now(),
		ExpiresAt:               cibaReq.ExpiresAt,
	}

	if err := h.q.Enqueue(queueReq); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to enqueue CIBA request",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"auth_req_id": authReqID,
		"expires_in":  expiresIn,
		"interval":    interval,
	})
}

func (h *Handler) HandleCIBAToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	authReqID := r.Form.Get("auth_req_id")
	if authReqID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "auth_req_id is required")
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	cibaReq, err := h.db.GetCIBARequest(authReqID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid auth_req_id")
		return
	}

	if time.Now().After(cibaReq.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "auth_req_id expired")
		return
	}

	client, err := h.db.GetClient(cibaReq.ClientID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client not found")
		return
	}

	if client.TokenEndpointAuthMethod != "none" {
		if clientID != cibaReq.ClientID || clientSecret != client.Secret {
			writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
			return
		}
	}

	switch cibaReq.Status {
	case "pending":
		writeTokenError(w, http.StatusBadRequest, "authorization_pending", "User has not yet authorized")
		return
	case "denied":
		writeTokenError(w, http.StatusBadRequest, "access_denied", "User denied the request")
		return
	case "expired":
		writeTokenError(w, http.StatusBadRequest, "expired_token", "Request expired")
		return
	}

	if cibaReq.Status != "approved" {
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
	queueReq, err := h.q.GetByID(authReqID)
	if err == nil && queueReq.UserID != "" {
		userID = queueReq.UserID
	} else {
		userID = cibaReq.UserID
	}

	scopes := crypto.NormalizeScopes("openid profile")

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  cibaReq.ClientID,
		UserID:    userID,
		Scopes:    scopes,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    cibaReq.ClientID,
		UserID:      userID,
		Scopes:      scopes,
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

	writeTokenResponse(w, accessToken, refreshToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), "Bearer", strings.Join(scopes, " "))
}

func (h *Handler) HandleCIBACallback(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	status := r.URL.Query().Get("status")

	if authReqID == "" || status == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
		return
	}

	switch status {
	case "approved":
		if err := h.db.UpdateCIBARequestStatus(authReqID, "approved"); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "server_error",
			})
			return
		}
		_ = h.q.Approve(authReqID, "")
	case "denied":
		if err := h.db.UpdateCIBARequestStatus(authReqID, "denied"); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "server_error",
			})
			return
		}
		_ = h.q.Deny(authReqID, "User denied")
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) HandleCIBAApprove(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	userID := r.URL.Query().Get("user_id")

	if authReqID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "auth_req_id is required",
		})
		return
	}

	// Update CIBA request status (best effort)
	_ = h.db.UpdateCIBARequestStatus(authReqID, "approved")

	// Update device code status (best effort)
	_ = h.db.UpdateDeviceCodeStatus(authReqID, "approved")

	if err := h.q.Approve(authReqID, userID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "approved",
	})
}

func (h *Handler) HandleCIBADeny(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	reason := r.URL.Query().Get("reason")

	if authReqID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "auth_req_id is required",
		})
		return
	}

	if err := h.db.UpdateCIBARequestStatus(authReqID, "denied"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to update request",
		})
		return
	}

	if err := h.q.Deny(authReqID, reason); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "denied",
	})
}

func (h *Handler) HandleCIBAPending(w http.ResponseWriter, r *http.Request) {
	requests, err := h.db.GetPendingCIBARequests()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
		return
	}

	writeJSON(w, http.StatusOK, requests)
}

func (h *Handler) HandleCIBAPoll(w http.ResponseWriter, r *http.Request) {
	interval := h.cfg.Queue.PollInterval
	ctx := r.Context()

	ch := h.q.Poll(ctx, interval)

	select {
	case req := <-ch:
		writeJSON(w, http.StatusOK, req)
	case <-ctx.Done():
		writeJSON(w, http.StatusOK, map[string]string{"status": "timeout"})
	case <-time.After(30 * time.Second):
		writeJSON(w, http.StatusOK, map[string]string{"status": "no_pending_requests"})
	}
}
