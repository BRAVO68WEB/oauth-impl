package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/server"
)

func setupTestServer(t *testing.T) (*httptest.Server, func()) {
	dbPath := "test_integration_" + t.Name() + ".db"
	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	if err := db.Migrate(); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Security.RequirePKCE = false

	q := queue.NewMemoryQueue(100)

	srv, err := server.New(cfg, db, q)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ts := httptest.NewServer(srv.GetRouter())

	cleanup := func() {
		ts.Close()
		func() { _ = db.Close() }()
		func() { _ = os.Remove(dbPath) }()
	}

	return ts, cleanup
}

func TestHealthEndpoint(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %q", result["status"])
	}
}

func TestClientRegistration(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"authorization_code"},
		"scope":         "openid profile",
	}

	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result["client_id"] == nil {
		t.Error("Expected client_id in response")
	}
	if result["client_secret"] == nil {
		t.Error("Expected client_secret in response")
	}
}

func TestClientCredentialsFlow(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	regBody := map[string]interface{}{
		"client_name":   "M2M Client",
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"client_credentials"},
		"scope":         "openid",
	}

	jsonBody, _ := json.Marshal(regBody)
	regResp, _ := http.Post(ts.URL+"/oauth/register", "application/json", bytes.NewBuffer(jsonBody))

	var client map[string]interface{}
	if err := json.NewDecoder(regResp.Body).Decode(&client); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	func() { _ = regResp.Body.Close() }()

	clientID := client["client_id"].(string)
	clientSecret := client["client_secret"].(string)

	tokenBody := "grant_type=client_credentials&scope=openid"
	req, _ := http.NewRequest("POST", ts.URL+"/oauth/token", bytes.NewBufferString(tokenBody))
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer func() { _ = tokenResp.Body.Close() }()

	if tokenResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", tokenResp.StatusCode)
	}

	var token map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&token); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if token["access_token"] == nil {
		t.Error("Expected access_token in response")
	}
	if token["token_type"] != "Bearer" {
		t.Errorf("Expected token_type 'Bearer', got %q", token["token_type"])
	}
}

func TestOIDCDiscovery(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Failed to get discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var discovery map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
		"registration_endpoint",
	}

	for _, field := range requiredFields {
		if discovery[field] == nil {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

func TestJWKSEndpoint(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/oidc/jwks")
	if err != nil {
		t.Fatalf("Failed to get JWKS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var jwks map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		t.Fatal("Expected keys array in JWKS")
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}
}
