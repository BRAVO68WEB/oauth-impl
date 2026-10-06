package oidc

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
)

func TestClaimMappingAndReservedSub(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.OIDC.ClaimMappings = []config.ClaimMapping{{Claim: "sub", Source: "username"}}
	if err := config.ValidatePlatform(cfg); err == nil {
		t.Fatal("sub must not be remapped")
	}

	db, err := database.New(filepath.Join(t.TempDir(), "claims.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg = config.DefaultConfig()
	cfg.OIDC.ClaimMappings = []config.ClaimMapping{{
		Claim: "department", Source: "attr.department", Scopes: []string{"profile"},
	}}
	if err := repository.NewUserRepository(db).Create(&models.User{
		ID: "user-1", Username: "ada", PasswordHash: "x",
		Attributes: map[string]string{"department": "engineering"},
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	withProfile, err := handler.CreateIDToken("app", "user-1", "nonce", []string{"openid", "profile"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := handler.ParseSignedToken(withProfile)
	if err != nil {
		t.Fatal(err)
	}
	if claims["department"] != "engineering" {
		t.Fatalf("department = %v", claims["department"])
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("sub = %v", claims["sub"])
	}
	without, err := handler.CreateIDToken("app", "user-1", "", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	bare, err := handler.ParseSignedToken(without)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bare["department"]; ok {
		t.Fatal("department present without profile")
	}
}

func TestSigningKeysSurviveRestartAndRotation(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	first, err := NewHandler(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, kid := first.GetKeySet().GetRSAKey()
	token, err := first.CreateIDToken("app", "user-1", "", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	db, err = database.New(filepath.Join(dir, "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	second, err := NewHandler(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, restarted := second.GetKeySet().GetRSAKey()
	if restarted != kid {
		t.Fatalf("kid changed across restart: %s -> %s", kid, restarted)
	}
	if _, err := second.ParseSignedToken(token); err != nil {
		t.Fatal(err)
	}
	if err := second.GetKeySet().Rotate(time.Hour); err != nil {
		t.Fatal(err)
	}
	_, active := second.GetKeySet().GetRSAKey()
	if active == kid {
		t.Fatal("rotate did not change the active kid")
	}
	jwks := second.GetKeySet().ToJWKS()
	seen := map[string]bool{}
	for _, key := range jwks.Keys {
		seen[key.Kid] = true
	}
	if !seen[kid] || !seen[active] {
		t.Fatalf("jwks kids = %v", seen)
	}
	if _, err := second.ParseSignedToken(token); err != nil {
		t.Fatalf("retired key should still verify: %v", err)
	}
}
