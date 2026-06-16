package controller

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/oauth-impl/internal/service"
)

type ManagementController struct {
	clientSvc *service.ClientService
	userSvc   *service.UserService
	tokenSvc  *service.TokenService
	totpSvc   *service.TOTPService
}

func NewManagementController(clientSvc *service.ClientService, userSvc *service.UserService, tokenSvc *service.TokenService, totpSvc *service.TOTPService) *ManagementController {
	return &ManagementController{
		clientSvc: clientSvc,
		userSvc:   userSvc,
		tokenSvc:  tokenSvc,
		totpSvc:   totpSvc,
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// ─── Client Management ────────────────────────────────────

func (c *ManagementController) HandleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := c.clientSvc.ListClients()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list clients")
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (c *ManagementController) HandleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                                string   `json:"name"`
		RedirectURIs                        []string `json:"redirect_uris"`
		GrantTypes                          []string `json:"grant_types"`
		Scopes                              []string `json:"scopes"`
		TokenEndpointAuthMethod             string   `json:"token_endpoint_auth_method"`
		DPoPBoundAccessTokens               bool     `json:"dpop_bound_access_tokens"`
		RequirePushedAuthorizationRequests  bool     `json:"require_pushed_authorization_requests"`
		BackchannelTokenDeliveryMode        string   `json:"backchannel_token_delivery_mode"`
		BackchannelClientNotificationEndpoint string `json:"backchannel_client_notification_endpoint"`
		BackchannelAuthenticationRequestSigningAlg string `json:"backchannel_authentication_request_signing_alg"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	client, err := c.clientSvc.CreateClient(service.CreateClientInput{
		Name:                                req.Name,
		RedirectURIs:                        req.RedirectURIs,
		GrantTypes:                          req.GrantTypes,
		Scopes:                              req.Scopes,
		TokenEndpointAuthMethod:             req.TokenEndpointAuthMethod,
		DPoPBoundAccessTokens:               req.DPoPBoundAccessTokens,
		RequirePushedAuthorizationRequests:  req.RequirePushedAuthorizationRequests,
		BackchannelTokenDeliveryMode:        req.BackchannelTokenDeliveryMode,
		BackchannelClientNotificationEndpoint: req.BackchannelClientNotificationEndpoint,
		BackchannelAuthenticationRequestSigningAlg: req.BackchannelAuthenticationRequestSigningAlg,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, client)
}

func (c *ManagementController) HandleGetClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	client, err := c.clientSvc.GetClient(clientID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Client not found")
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (c *ManagementController) HandleUpdateClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	existing, err := c.clientSvc.GetClient(clientID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Client not found")
		return
	}

	var req struct {
		Name                                string   `json:"name"`
		RedirectURIs                        []string `json:"redirect_uris"`
		GrantTypes                          []string `json:"grant_types"`
		Scopes                              []string `json:"scopes"`
		TokenEndpointAuthMethod             string   `json:"token_endpoint_auth_method"`
		DPoPBoundAccessTokens               bool     `json:"dpop_bound_access_tokens"`
		RequirePushedAuthorizationRequests  bool     `json:"require_pushed_authorization_requests"`
		BackchannelTokenDeliveryMode        string   `json:"backchannel_token_delivery_mode"`
		BackchannelClientNotificationEndpoint string `json:"backchannel_client_notification_endpoint"`
		BackchannelAuthenticationRequestSigningAlg string `json:"backchannel_authentication_request_signing_alg"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.RedirectURIs != nil {
		existing.RedirectURIs = req.RedirectURIs
	}
	if req.GrantTypes != nil {
		existing.GrantTypes = req.GrantTypes
	}
	if req.Scopes != nil {
		existing.Scopes = req.Scopes
	}
	if req.TokenEndpointAuthMethod != "" {
		existing.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}
	existing.DPoPBoundAccessTokens = req.DPoPBoundAccessTokens
	existing.RequirePushedAuthorizationRequests = req.RequirePushedAuthorizationRequests
	existing.BackchannelTokenDeliveryMode = req.BackchannelTokenDeliveryMode
	existing.BackchannelClientNotificationEndpoint = req.BackchannelClientNotificationEndpoint
	existing.BackchannelAuthenticationRequestSigningAlg = req.BackchannelAuthenticationRequestSigningAlg

	if err := c.clientSvc.UpdateClient(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to update client")
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

func (c *ManagementController) HandleDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	if err := c.clientSvc.DeleteClient(clientID); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to delete client")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ─── User Management ──────────────────────────────────────

func (c *ManagementController) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := c.userSvc.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (c *ManagementController) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Phone    string `json:"phone_number"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	user, err := c.userSvc.CreateUser(req.Username, req.Password, req.Email, req.Phone)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (c *ManagementController) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	user, err := c.userSvc.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// ─── Token Management ─────────────────────────────────────

func (c *ManagementController) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	userID := r.URL.Query().Get("user_id")

	tokens, err := c.tokenSvc.ListTokens(clientID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list tokens")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (c *ManagementController) HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if err := c.tokenSvc.RevokeToken(token); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to revoke token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ─── MFA Management ───────────────────────────────────────

func (c *ManagementController) HandleMFAEnable(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	user, err := c.userSvc.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	result, err := c.totpSvc.EnableMFA(userID, user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to enable MFA: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret":     result.Secret,
		"qr_uri":     result.QRCodeURI,
		"qr_base64":  result.QRBase64,
	})
}

func (c *ManagementController) HandleMFAVerify(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	var req struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	if err := c.totpSvc.ConfirmMFA(userID, req.Code); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_enabled"})
}

func (c *ManagementController) HandleMFAStatus(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	enabled, err := c.totpSvc.IsMFAEnabled(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":       userID,
		"mfa_enabled":   enabled,
	})
}

func (c *ManagementController) HandleMFADisable(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	if err := c.totpSvc.DisableMFA(userID); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to disable MFA")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_disabled"})
}
