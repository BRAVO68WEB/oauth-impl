package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	root "github.com/bravo68web/oauth-impl"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/controller"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/handlers/oauth"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/route"
	"github.com/bravo68web/oauth-impl/internal/service"
)

func main() {
	configPath := flag.String("config", "", "Path to config file")
	port := flag.Int("port", 0, "Server port (overrides config)")
	dbPath := flag.String("db", "", "Database path (overrides config)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *port > 0 {
		cfg.Server.Port = *port
	}
	if *dbPath != "" {
		cfg.Database.Path = *dbPath
	}

	if err := os.MkdirAll(".", 0755); err != nil {
		log.Fatalf("Failed to create directories: %v", err)
	}

	// Database
	db, err := database.New(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	if cfg.Database.Migrations {
		if err := db.Migrate(); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}
		log.Println("Database migrations completed")
	}

	conn := db.Conn()

	// Repositories
	clientRepo := repository.NewClientRepository(conn)
	userRepo := repository.NewUserRepository(conn)
	tokenRepo := repository.NewTokenRepository(conn)
	authCodeRepo := repository.NewAuthCodeRepository(conn)

	// OIDC handler (generates RSA + EC keys on startup)
	oidcHandler, err := oidc.NewHandler(db, cfg)
	if err != nil {
		log.Fatalf("Failed to create OIDC handler: %v", err)
	}

	// Queue
	q := queue.NewMemoryQueue(cfg.Queue.MaxPending)

	// Services
	totpSvc := service.NewTOTPService(userRepo, &cfg.Security.MFA)
	userSvc := service.NewUserService(userRepo, totpSvc, &cfg.Security)
	clientSvc := service.NewClientService(clientRepo)
	tokenSvc := service.NewTokenService(tokenRepo, authCodeRepo, oidcHandler, &cfg.Security)

	// OAuth handler (legacy, still uses database.DB directly)
	oauthHandler := oauth.NewHandler(db, cfg, q, oidcHandler)

	// Controllers
	mgmtCtrl := controller.NewManagementController(clientSvc, userSvc, tokenSvc, totpSvc)
	webCtrl, err := controller.NewWebController(userSvc, totpSvc, cfg, root.TemplateFS, oauthHandler)
	if err != nil {
		log.Fatalf("Failed to create web controller: %v", err)
	}

	// Router
	router := route.NewRouter(mgmtCtrl, webCtrl, oauthHandler, oidcHandler, root.OpenAPISpec, root.TemplateFS)

	// HTTP server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router.GetMux(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Printf(`
╔══════════════════════════════════════════════════════════════╗
║                    OAuth Implementation Server               ║
╠══════════════════════════════════════════════════════════════╣
║  Server:      http://%s:%d                           ║
║  Database:    %-46s ║
║  Queue:       %-46s ║
║  MFA:         %-46s ║
╚══════════════════════════════════════════════════════════════╝

Endpoints:
  OAuth 2.0:
    POST /oauth/authorize     - Authorization endpoint
    POST /oauth/token         - Token endpoint
    POST /oauth/revoke        - Token revocation (RFC 7009)
    POST /oauth/introspect    - Token introspection (RFC 7662)
    POST /oauth/register      - Dynamic client registration (RFC 7591)
    POST /oauth/device        - Device authorization (RFC 8628)
    POST /oauth/par           - Pushed authorization requests (RFC 9126)
    POST /oauth/bc-authorize  - CIBA backchannel authentication

  OIDC:
    GET  /.well-known/openid-configuration
    GET  /.well-known/oauth-authorization-server
    GET  /oidc/userinfo
    GET  /oidc/jwks

  Web:
    GET  /login               - Login page
    GET  /register            - Registration page
    GET  /consent             - OIDC consent screen
    GET  /mfa/enroll          - MFA enrollment with QR code

  API Documentation:
    GET  /docs                - Scalar API docs UI
    GET  /openapi             - OpenAPI spec (JSON)
    GET  /docs/openapi.yaml   - OpenAPI spec (YAML)

  Management API:
    GET/POST   /api/clients
    GET/PUT/DELETE /api/clients/{id}
    GET/POST   /api/users
    GET        /api/users/{id}
    GET        /api/tokens
    POST       /api/tokens/{token}/revoke
    GET        /api/ciba/pending
    POST       /api/ciba/{id}/approve
    POST       /api/ciba/{id}/deny

  Health:
    GET  /health

`, cfg.Server.Host, cfg.Server.Port, cfg.Database.Path, cfg.Queue.Type, mfaStatus(cfg))

	// Start server
	go func() {
		log.Printf("Starting OAuth server on %s", httpServer.Addr)
		if cfg.Server.TLS.Enabled {
			if err := httpServer.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
		} else {
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	httpServer.Close()
}

func mfaStatus(cfg *config.Config) string {
	if cfg.Security.MFA.Required {
		return "required (all users)"
	}
	if cfg.Security.MFA.Enabled {
		return "enabled (optional)"
	}
	return "disabled"
}
