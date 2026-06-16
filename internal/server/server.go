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
	"golang.org/x/crypto/bcrypt"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/handlers/oauth"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

type Server struct {
	cfg          *config.Config
	db           *database.DB
	queue        *queue.MemoryQueue
	router       *chi.Mux
	server       *http.Server
	oauthHandler *oauth.Handler
	oidcHandler  *oidc.Handler
	clientRepo   *repository.ClientRepository
	userRepo     *repository.UserRepository
	tokenRepo    *repository.TokenRepository
	cibaRepo     *repository.CIBARepository
	scopeRepo    *repository.ScopeRepository
	resourceRepo *repository.ResourceRepository
	consentRepo  *repository.ConsentRepository
}

func New(cfg *config.Config, db *database.DB, q *queue.MemoryQueue) (*Server, error) {
	conn := db.Conn()

	// Repositories
	clientRepo := repository.NewClientRepository(conn)
	userRepo := repository.NewUserRepository(conn)
	tokenRepo := repository.NewTokenRepository(conn)
	authCodeRepo := repository.NewAuthCodeRepository(conn)
	deviceRepo := repository.NewDeviceCodeRepository(conn)
	cibaRepo := repository.NewCIBARepository(conn)
	parRepo := repository.NewPARRepository(conn)
	consentRepo := repository.NewConsentRepository(conn)
	scopeRepo := repository.NewScopeRepository(conn)
	resourceRepo := repository.NewResourceRepository(conn)

	oidcHandler, err := oidc.NewHandler(db, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC handler: %w", err)
	}

	// Services
	dpopSvc := service.NewDPoPService()
	mtlsSvc := service.NewMTLSService()
	jarSvc := service.NewJARService(cfg.Security.Issuer)

	oauthHandler := oauth.NewHandler(clientRepo, userRepo, tokenRepo, authCodeRepo, deviceRepo, cibaRepo, parRepo, consentRepo, dpopSvc, mtlsSvc, jarSvc, cfg, q, oidcHandler)

	s := &Server{
		cfg:          cfg,
		db:           db,
		queue:        q,
		oauthHandler: oauthHandler,
		oidcHandler:  oidcHandler,
		clientRepo:   clientRepo,
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		cibaRepo:     cibaRepo,
		scopeRepo:    scopeRepo,
		resourceRepo: resourceRepo,
		consentRepo:  consentRepo,
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

	// Security headers
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self' https://cdn.jsdelivr.net")
			next.ServeHTTP(w, req)
		})
	})

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
			r.Get("/pending", s.handleCIBAPending)
			r.Post("/{authReqID}/approve", s.handleCIBAApprove)
			r.Post("/{authReqID}/deny", s.handleCIBADeny)
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
		r.Post("/bc-authorize", s.oauthHandler.HandleBCAuthorize)
	})

	r.Route("/device", func(r chi.Router) {
		r.Get("/", s.oauthHandler.HandleDeviceVerification)
		r.Post("/", s.oauthHandler.HandleDeviceVerification)
	})

	r.Route("/ciba", func(r chi.Router) {
		r.Get("/pending", s.oauthHandler.HandleCIBAListPending)
		r.Get("/status", s.oauthHandler.HandleCIBAStatus)
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

	r.Get("/login", s.handleLogin)
	r.Get("/register", s.handleRegisterPage)
	r.Get("/consent", s.handleConsent)

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.clientRepo.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to list clients",
		})
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var client models.Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
		return
	}

	if client.ID == "" {
		client.ID = uuid.New().String()
	}
	if client.Secret == "" {
		secret, err := crypto.GenerateToken()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Failed to generate secret",
			})
			return
		}
		client.Secret = secret
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code"}
	}
	if len(client.Scopes) == 0 {
		client.Scopes = []string{"openid", "profile", "email"}
	}
	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = "client_secret_basic"
	}
	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()

	if err := s.clientRepo.Create(&client); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create client",
		})
		return
	}

	writeJSON(w, http.StatusCreated, client)
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "client_id is required",
		})
		return
	}

	client, err := s.clientRepo.GetByID(clientID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "Client not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, client)
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "client_id is required",
		})
		return
	}

	existing, err := s.clientRepo.GetByID(clientID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "Client not found",
		})
		return
	}

	var update models.Client
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
		return
	}

	if update.Name != "" {
		existing.Name = update.Name
	}
	if len(update.RedirectURIs) > 0 {
		existing.RedirectURIs = update.RedirectURIs
	}
	if len(update.GrantTypes) > 0 {
		existing.GrantTypes = update.GrantTypes
	}
	if len(update.Scopes) > 0 {
		existing.Scopes = update.Scopes
	}
	if update.TokenEndpointAuthMethod != "" {
		existing.TokenEndpointAuthMethod = update.TokenEndpointAuthMethod
	}
	existing.DPoPBoundAccessTokens = update.DPoPBoundAccessTokens
	existing.RequirePushedAuthorizationRequests = update.RequirePushedAuthorizationRequests
	existing.UpdatedAt = time.Now()

	if err := s.clientRepo.Update(existing); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to update client",
		})
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "client_id is required",
		})
		return
	}

	if err := s.clientRepo.Delete(clientID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to delete client",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Client deleted",
	})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.userRepo.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to list users",
		})
		return
	}

	// Strip password hashes from response
	type safeUser struct {
		ID          string    `json:"id"`
		Username    string    `json:"username"`
		Email       string    `json:"email,omitempty"`
		PhoneNumber string    `json:"phone_number,omitempty"`
		CreatedAt   time.Time `json:"created_at"`
	}

	safeUsers := make([]safeUser, len(users))
	for i, u := range users {
		safeUsers[i] = safeUser{
			ID:          u.ID,
			Username:    u.Username,
			Email:       u.Email,
			PhoneNumber: u.PhoneNumber,
			CreatedAt:   u.CreatedAt,
		}
	}

	writeJSON(w, http.StatusOK, safeUsers)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email,omitempty"`
		Phone    string `json:"phone_number,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
		return
	}

	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "username and password are required",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to hash password",
		})
		return
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		PasswordHash: string(hash),
		Email:        req.Email,
		PhoneNumber:  req.Phone,
		CreatedAt:    time.Now(),
	}

	if err := s.userRepo.Create(user); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "Username already exists",
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":       user.ID,
		"username": user.Username,
		"message":  "User created",
	})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "user_id is required",
		})
		return
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "User not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":           user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"phone_number": user.PhoneNumber,
		"created_at":   user.CreatedAt,
	})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	userID := r.URL.Query().Get("user_id")

	tokens, err := s.tokenRepo.ListAccessTokens(clientID, userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to list tokens",
		})
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "token is required",
		})
		return
	}

	if err := s.tokenRepo.RevokeAccessToken(token); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "Token not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Token revoked",
	})
}

func (s *Server) handleCIBAPending(w http.ResponseWriter, r *http.Request) {
	requests, err := s.cibaRepo.GetPending()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to list pending CIBA requests",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending_requests": requests,
	})
}

func (s *Server) handleCIBAApprove(w http.ResponseWriter, r *http.Request) {
	authReqID := chi.URLParam(r, "authReqID")
	if authReqID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "auth_req_id is required",
		})
		return
	}

	if err := s.cibaRepo.UpdateStatus(authReqID, "approved"); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "CIBA request not found",
		})
		return
	}

	_ = s.queue.Approve(authReqID, "")

	writeJSON(w, http.StatusOK, map[string]string{
		"auth_req_id": authReqID,
		"status":      "approved",
	})
}

func (s *Server) handleCIBADeny(w http.ResponseWriter, r *http.Request) {
	authReqID := chi.URLParam(r, "authReqID")
	if authReqID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "auth_req_id is required",
		})
		return
	}

	if err := s.cibaRepo.UpdateStatus(authReqID, "denied"); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "CIBA request not found",
		})
		return
	}

	_ = s.queue.Deny(authReqID, "Denied by admin")

	writeJSON(w, http.StatusOK, map[string]string{
		"auth_req_id": authReqID,
		"status":      "denied",
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<h1>Login</h1>
<form method="POST" action="/oauth/authorize">
	<label>Username: <input type="text" name="username" required></label><br>
	<label>Password: <input type="password" name="password" required></label><br>
	<input type="hidden" name="client_id" value="%s">
	<input type="hidden" name="redirect_uri" value="%s">
	<input type="hidden" name="response_type" value="%s">
	<input type="hidden" name="scope" value="%s">
	<input type="hidden" name="state" value="%s">
	<button type="submit">Login</button>
</form>
</body>
</html>`,
		r.URL.Query().Get("client_id"),
		r.URL.Query().Get("redirect_uri"),
		r.URL.Query().Get("response_type"),
		r.URL.Query().Get("scope"),
		r.URL.Query().Get("state"),
	)
}

func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Register</title></head>
<body>
<h1>Register</h1>
<form method="POST" action="/api/users">
	<label>Username: <input type="text" name="username" required></label><br>
	<label>Password: <input type="password" name="password" required></label><br>
	<label>Email: <input type="email" name="email"></label><br>
	<button type="submit">Register</button>
</form>
</body>
</html>`)
}

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Consent</title></head>
<body>
<h1>Authorize Application</h1>
<p>The application requests access to:</p>
<ul>
	<li>openid</li>
	<li>profile</li>
	<li>email</li>
</ul>
<form method="POST" action="/oauth/authorize">
	<input type="hidden" name="client_id" value="%s">
	<input type="hidden" name="redirect_uri" value="%s">
	<input type="hidden" name="response_type" value="%s">
	<input type="hidden" name="scope" value="%s">
	<input type="hidden" name="state" value="%s">
	<input type="hidden" name="consent" value="true">
	<button type="submit">Allow</button>
	<button type="submit" name="deny" value="true">Deny</button>
</form>
</body>
</html>`,
		r.URL.Query().Get("client_id"),
		r.URL.Query().Get("redirect_uri"),
		r.URL.Query().Get("response_type"),
		r.URL.Query().Get("scope"),
		r.URL.Query().Get("state"),
	)
}

func (s *Server) GetRouter() *chi.Mux {
	return s.router
}

func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	return s.server.Close()
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) StartWithGracefulShutdown() {
	go func() {
		log.Printf("Starting OAuth server on %s://%s:%d", "http", s.cfg.Server.Host, s.cfg.Server.Port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
