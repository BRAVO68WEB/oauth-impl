package management

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
)

type Handler struct {
	db *database.DB
}

func NewHandler(db *database.DB) *Handler {
	return &Handler{db: db}
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

func (h *Handler) HandleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.db.ListClients()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list clients")
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (h *Handler) HandleCreateClient(w http.ResponseWriter, r *http.Request) {
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

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Name is required")
		return
	}

	client := &models.Client{
		ID:                                  uuid.New().String(),
		Secret:                              uuid.New().String(),
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
		CreatedAt:                           time.Now(),
		UpdatedAt:                           time.Now(),
	}

	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if err := h.db.CreateClient(client); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to create client")
		return
	}

	writeJSON(w, http.StatusCreated, client)
}

func (h *Handler) HandleGetClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	client, err := h.db.GetClient(clientID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Client not found")
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (h *Handler) HandleUpdateClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	existing, err := h.db.GetClient(clientID)
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
	existing.UpdatedAt = time.Now()

	if err := h.db.UpdateClient(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to update client")
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

func (h *Handler) HandleDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	if err := h.db.DeleteClient(clientID); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to delete client")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.db.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (h *Handler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
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

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Username and password are required")
		return
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		PasswordHash: req.Password,
		Email:        req.Email,
		PhoneNumber:  req.Phone,
		CreatedAt:    time.Now(),
	}

	if err := h.db.CreateUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (h *Handler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	user, err := h.db.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	userID := r.URL.Query().Get("user_id")

	tokens, err := h.db.ListAccessTokens(clientID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list tokens")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (h *Handler) HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if err := h.db.RevokeAccessToken(token); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to revoke token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
