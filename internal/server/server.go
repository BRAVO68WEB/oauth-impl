package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/handlers/oauth"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/queue"
)

type Server struct {
	cfg          *config.Config
	db           *database.DB
	queue        *queue.MemoryQueue
	router       *chi.Mux
	server       *http.Server
	oauthHandler *oauth.Handler
	oidcHandler  *oidc.Handler
}

func New(cfg *config.Config, db *database.DB, q *queue.MemoryQueue) (*Server, error) {
	oidcHandler, err := oidc.NewHandler(db, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC handler: %w", err)
	}

	oauthHandler := oauth.NewHandler(db, cfg, q, oidcHandler)

	s := &Server{
		cfg:          cfg,
		db:           db,
		queue:        q,
		oauthHandler: oauthHandler,
		oidcHandler:  oidcHandler,
	}

	s.router = s.setupRouter()
	s.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

func (s *Server) setupRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "DPoP"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/health", s.handleHealth)

	r.Route("/api", func(r chi.Router) {
		r.Route("/clients", func(r chi.Router) {
			r.Get("/", s.handleListClients)
			r.Post("/", s.handleCreateClient)
			r.Get("/{clientID}", s.handleGetClient)
			r.Put("/{clientID}", s.handleUpdateClient)
			r.Delete("/{clientID}", s.handleDeleteClient)
		})

		r.Route("/users", func(r chi.Router) {
			r.Get("/", s.handleListUsers)
			r.Post("/", s.handleCreateUser)
			r.Get("/{userID}", s.handleGetUser)
		})

		r.Route("/tokens", func(r chi.Router) {
			r.Get("/", s.handleListTokens)
			r.Post("/{token}/revoke", s.handleRevokeToken)
		})

		r.Route("/ciba", func(r chi.Router) {
			r.Get("/pending", s.handleGetPendingCIBA)
			r.Post("/{authReqID}/approve", s.handleApproveCIBA)
			r.Post("/{authReqID}/deny", s.handleDenyCIBA)
		})
	})

	r.Route("/oauth", func(r chi.Router) {
		r.Get("/authorize", s.oauthHandler.HandleAuthorize)
		r.Post("/authorize", s.oauthHandler.HandleAuthorize)
		r.Post("/token", s.oauthHandler.HandleToken)
		r.Post("/revoke", s.oauthHandler.HandleRevoke)
		r.Post("/introspect", s.oauthHandler.HandleIntrospect)
		r.Post("/register", s.oauthHandler.HandleRegister)
		r.Post("/device", s.oauthHandler.HandleDeviceAuthorization)
		r.Post("/par", s.oauthHandler.HandlePAR)
		r.Post("/bc-authorize", s.oauthHandler.HandleCIBA)
	})

	r.Route("/device", func(r chi.Router) {
		r.Get("/", s.oauthHandler.HandleDeviceVerification)
		r.Post("/", s.oauthHandler.HandleDeviceVerification)
	})

	r.Route("/ciba", func(r chi.Router) {
		r.Get("/pending", s.oauthHandler.HandleCIBAPending)
		r.Get("/poll", s.oauthHandler.HandleCIBAPoll)
		r.Post("/approve", s.oauthHandler.HandleCIBAApprove)
		r.Post("/deny", s.oauthHandler.HandleCIBADeny)
	})

	r.Route("/.well-known", func(r chi.Router) {
		r.Get("/openid-configuration", s.oidcHandler.HandleDiscovery)
		r.Get("/oauth-authorization-server", s.oidcHandler.HandleASMetadata)
	})

	r.Route("/oidc", func(r chi.Router) {
		r.Get("/userinfo", s.oidcHandler.HandleUserInfo)
		r.Get("/jwks", s.oidcHandler.HandleJWKS)
	})

	return r
}

func (s *Server) Start() error {
	go func() {
		log.Printf("Starting OAuth server on %s", s.server.Addr)
		if s.cfg.Server.TLS.Enabled {
			if err := s.server.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
		} else {
			if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.queue.StartCleanup(ctx, 1*time.Minute)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	return s.server.Shutdown(shutdownCtx)
}

func (s *Server) GetRouter() *chi.Mux {
	return s.router
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code string, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.db.ListClients()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list clients")
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
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

	if err := s.db.CreateClient(client); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to create client")
		return
	}

	writeJSON(w, http.StatusCreated, client)
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	client, err := s.db.GetClient(clientID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Client not found")
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	existing, err := s.db.GetClient(clientID)
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

	if err := s.db.UpdateClient(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to update client")
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	if err := s.db.DeleteClient(clientID); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to delete client")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
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

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to hash password")
		return
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		PasswordHash: hashedPassword,
		Email:        req.Email,
		PhoneNumber:  req.Phone,
		CreatedAt:    time.Now(),
	}

	if err := s.db.CreateUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	user, err := s.db.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	userID := r.URL.Query().Get("user_id")

	tokens, err := s.db.ListAccessTokens(clientID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list tokens")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if err := s.db.RevokeAccessToken(token); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to revoke token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleGetPendingCIBA(w http.ResponseWriter, r *http.Request) {
	s.oauthHandler.HandleCIBAPending(w, r)
}

func (s *Server) handleApproveCIBA(w http.ResponseWriter, r *http.Request) {
	s.oauthHandler.HandleCIBAApprove(w, r)
}

func (s *Server) handleDenyCIBA(w http.ResponseWriter, r *http.Request) {
	s.oauthHandler.HandleCIBADeny(w, r)
}

func hashPassword(password string) (string, error) {
	bytes, err := hashPasswordBytes([]byte(password))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func hashPasswordBytes(password []byte) ([]byte, error) {
	return password, nil
}
