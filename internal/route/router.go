package route

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"gopkg.in/yaml.v3"

	"github.com/bravo68web/oauth-impl/internal/controller"
	"github.com/bravo68web/oauth-impl/internal/handlers/oauth"
	"github.com/bravo68web/oauth-impl/internal/oidc"
)

type Router struct {
	mux            *chi.Mux
	managementCtrl *controller.ManagementController
	webCtrl        *controller.WebController
	oauthHandler   *oauth.Handler
	oidcHandler    *oidc.Handler
	openapiJSON    []byte
	templateFS     embed.FS
}

func NewRouter(
	managementCtrl *controller.ManagementController,
	webCtrl *controller.WebController,
	oauthHandler *oauth.Handler,
	oidcHandler *oidc.Handler,
	openapiSpec []byte,
	templateFS embed.FS,
) *Router {
	openapiJSON, err := convertYAMLBytesToJSON(openapiSpec)
	if err != nil {
		log.Printf("WARNING: Failed to convert OpenAPI spec to JSON: %v", err)
		openapiJSON = []byte("{}")
	}

	r := &Router{
		mux:            chi.NewRouter(),
		managementCtrl: managementCtrl,
		webCtrl:        webCtrl,
		oauthHandler:   oauthHandler,
		oidcHandler:    oidcHandler,
		openapiJSON:    openapiJSON,
		templateFS:     templateFS,
	}

	r.setupMiddleware()
	r.setupRoutes()

	return r
}

func (r *Router) setupMiddleware() {
	r.mux.Use(middleware.RequestID)
	r.mux.Use(middleware.Logger)
	r.mux.Use(middleware.Recoverer)
	r.mux.Use(middleware.Timeout(60 * time.Second))

	r.mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "DPoP"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
}

func (r *Router) setupRoutes() {
	r.mux.Get("/health", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
		})
	})

	r.mux.Route("/api", func(r2 chi.Router) {
		r2.Route("/clients", func(r3 chi.Router) {
			r3.Get("/", r.managementCtrl.HandleListClients)
			r3.Post("/", r.managementCtrl.HandleCreateClient)
			r3.Get("/{clientID}", r.managementCtrl.HandleGetClient)
			r3.Put("/{clientID}", r.managementCtrl.HandleUpdateClient)
			r3.Delete("/{clientID}", r.managementCtrl.HandleDeleteClient)
		})

		r2.Route("/users", func(r3 chi.Router) {
			r3.Get("/", r.managementCtrl.HandleListUsers)
			r3.Post("/", r.managementCtrl.HandleCreateUser)
			// MFA routes must be before /{userID} to avoid conflicts
			r3.Post("/{userID}/mfa/enable", r.managementCtrl.HandleMFAEnable)
			r3.Post("/{userID}/mfa/verify", r.managementCtrl.HandleMFAVerify)
			r3.Get("/{userID}/mfa/status", r.managementCtrl.HandleMFAStatus)
			r3.Post("/{userID}/mfa/disable", r.managementCtrl.HandleMFADisable)
			r3.Get("/{userID}", r.managementCtrl.HandleGetUser)
		})

		r2.Route("/tokens", func(r3 chi.Router) {
			r3.Get("/", r.managementCtrl.HandleListTokens)
			r3.Post("/{token}/revoke", r.managementCtrl.HandleRevokeToken)
		})

		r2.Route("/ciba", func(r3 chi.Router) {
			r3.Get("/pending", r.oauthHandler.HandleCIBAPending)
			r3.Post("/{authReqID}/approve", r.oauthHandler.HandleCIBAApprove)
			r3.Post("/{authReqID}/deny", r.oauthHandler.HandleCIBADeny)
		})
	})

	r.mux.Route("/oauth", func(r2 chi.Router) {
		r2.Get("/authorize", r.oauthHandler.HandleAuthorize)
		r2.Post("/authorize", r.oauthHandler.HandleAuthorize)
		r2.Post("/token", r.oauthHandler.HandleToken)
		r2.Post("/revoke", r.oauthHandler.HandleRevoke)
		r2.Post("/introspect", r.oauthHandler.HandleIntrospect)
		r2.Post("/register", r.oauthHandler.HandleRegister)
		r2.Post("/device", r.oauthHandler.HandleDeviceAuthorization)
		r2.Post("/par", r.oauthHandler.HandlePAR)
		r2.Post("/bc-authorize", r.oauthHandler.HandleCIBA)
	})

	r.mux.Route("/device", func(r2 chi.Router) {
		r2.Get("/", r.oauthHandler.HandleDeviceVerification)
		r2.Post("/", r.oauthHandler.HandleDeviceVerification)
	})

	r.mux.Route("/ciba", func(r2 chi.Router) {
		r2.Get("/pending", r.oauthHandler.HandleCIBAPending)
		r2.Get("/poll", r.oauthHandler.HandleCIBAPoll)
		r2.Post("/approve", r.oauthHandler.HandleCIBAApprove)
		r2.Post("/deny", r.oauthHandler.HandleCIBADeny)
	})

	r.mux.Route("/.well-known", func(r2 chi.Router) {
		r2.Get("/openid-configuration", r.oidcHandler.HandleDiscovery)
		r2.Get("/oauth-authorization-server", r.oidcHandler.HandleASMetadata)
	})

	r.mux.Route("/oidc", func(r2 chi.Router) {
		r2.Get("/userinfo", r.oidcHandler.HandleUserInfo)
		r2.Get("/jwks", r.oidcHandler.HandleJWKS)
	})

	r.mux.Route("/login", func(r2 chi.Router) {
		r2.Get("/", r.webCtrl.HandleLoginPage)
		r2.Post("/", r.webCtrl.HandleLogin)
	})

	r.mux.Route("/login/mfa", func(r2 chi.Router) {
		r2.Post("/", r.webCtrl.HandleMFA)
	})

	r.mux.Route("/register", func(r2 chi.Router) {
		r2.Get("/", r.webCtrl.HandleRegisterPage)
		r2.Post("/", r.webCtrl.HandleRegister)
	})

	r.mux.Route("/consent", func(r2 chi.Router) {
		r2.Get("/", r.webCtrl.HandleConsentPage)
		r2.Post("/", r.webCtrl.HandleConsent)
	})

	r.mux.Route("/mfa", func(r2 chi.Router) {
		r2.Get("/enroll", r.webCtrl.HandleMFAEnrollPage)
		r2.Post("/enroll/verify", r.webCtrl.HandleMFAEnrollVerify)
	})

	// OpenAPI spec as JSON
	r.mux.Get("/openapi", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(r.openapiJSON)
	})

	// OpenAPI spec as YAML
	r.mux.Get("/docs/openapi.yaml", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		http.ServeFile(w, req, "openapi/spec.yaml")
	})

	// Scalar API docs UI
	r.mux.Get("/docs", func(w http.ResponseWriter, req *http.Request) {
		tmpl, err := template.ParseFS(r.templateFS, "internal/templates/docs.html")
		if err != nil {
			http.Error(w, "Failed to load docs page", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, nil)
	})
}

func (r *Router) GetMux() *chi.Mux {
	return r.mux
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func convertYAMLBytesToJSON(yamlData []byte) ([]byte, error) {
	var result map[string]interface{}
	if err := yaml.Unmarshal(yamlData, &result); err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
