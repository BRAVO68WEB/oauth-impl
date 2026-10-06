package database_test

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
)

func pgID(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return "pg-" + hex.EncodeToString(buf)
}

func TestPostgresMigrateRoundTrip(t *testing.T) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN is not set")
	}
	cfg := config.DefaultConfig()
	cfg.Database.Driver = "postgres"
	cfg.Database.DSN = dsn
	db, err := database.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	id := pgID(t)
	users := repository.NewUserRepository(db)
	if err := users.Create(&models.User{
		ID: id, Username: "user-" + id, PasswordHash: "hash",
		Email: "user@example.com", EmailVerified: true, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := users.GetByUsername("user-" + id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id || !got.EmailVerified {
		t.Fatalf("user = %+v", got)
	}

	clients := repository.NewClientRepository(db)
	now := time.Now().UTC().Truncate(time.Second)
	if err := clients.Create(&models.Client{
		ID: id, Secret: "secret", Name: "Postgres App",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		DCREnabled:              true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	client, err := clients.GetByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if client.Name != "Postgres App" || !client.DCREnabled || client.CreatedAt.IsZero() {
		t.Fatalf("client = %+v", client)
	}
}
