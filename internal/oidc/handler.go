package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
)

type Handler struct {
	db     *database.DB
	cfg    *config.Config
	keySet *KeySet
}

type KeySet struct {
	mu     sync.RWMutex
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	rsaKid string
	ecKid  string
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewHandler(db *database.DB, cfg *config.Config) (*Handler, error) {
	keySet, err := NewKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key set: %w", err)
	}

	return &Handler{
		db:     db,
		cfg:    cfg,
		keySet: keySet,
	}, nil
}

func NewKeySet() (*KeySet, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC key: %w", err)
	}

	rsaKid := generateKid()
	ecKid := generateKid()

	return &KeySet{
		rsaKey: rsaKey,
		ecKey:  ecKey,
		rsaKid: rsaKid,
		ecKid:  ecKid,
	}, nil
}

func generateKid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (ks *KeySet) GetRSAKey() (*rsa.PrivateKey, string) {
	return ks.rsaKey, ks.rsaKid
}

func (ks *KeySet) GetECKey() (*ecdsa.PrivateKey, string) {
	return ks.ecKey, ks.ecKid
}

func (ks *KeySet) GetPublicKey(kid string) interface{} {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if kid == ks.rsaKid {
		return &ks.rsaKey.PublicKey
	}
	if kid == ks.ecKid {
		return &ks.ecKey.PublicKey
	}
	return nil
}

func (ks *KeySet) ToJWKS() JWKS {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	rsaN := base64.RawURLEncoding.EncodeToString(ks.rsaKey.N.Bytes())
	rsaE := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(ks.rsaKey.PublicKey.E)).Bytes())

	// Get EC public key coordinates via ECDH API (non-deprecated)
	ecdhKey, _ := ks.ecKey.PublicKey.ECDH()
	ecPubBytes := ecdhKey.Bytes()
	// Uncompressed format: 0x04 || X || Y (each 32 bytes for P-256)
	ecX := base64.RawURLEncoding.EncodeToString(ecPubBytes[1:33])
	ecY := base64.RawURLEncoding.EncodeToString(ecPubBytes[33:65])

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Kid: ks.rsaKid,
				Use: "sig",
				Alg: "RS256",
				N:   rsaN,
				E:   rsaE,
			},
			{
				Kty: "EC",
				Kid: ks.ecKid,
				Use: "sig",
				Alg: "ES256",
				Crv: "P-256",
				X:   ecX,
				Y:   ecY,
			},
		},
	}
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce             string `json:"nonce,omitempty"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	AtHash            string `json:"at_hash,omitempty"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Sub               string `json:"sub"`
}

func (h *Handler) CreateIDToken(clientID, userID, nonce string, scopes []string) (string, error) {
	issuer := h.cfg.Security.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", h.cfg.Server.Port)
	}

	now := time.Now()
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Sub:   userID,
		Nonce: nonce,
	}

	for _, scope := range scopes {
		switch scope {
		case "profile":
			if user, err := h.db.GetUser(userID); err == nil {
				claims.Name = user.Username
				claims.PreferredUsername = user.Username
			}
		case "email":
			if user, err := h.db.GetUser(userID); err == nil {
				claims.Email = user.Email
				claims.EmailVerified = user.Email != ""
			}
		}
	}

	key, kid := h.keySet.GetRSAKey()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	return token.SignedString(key)
}

func (h *Handler) CreateIDTokenWithES256(clientID, userID, nonce string, scopes []string) (string, error) {
	issuer := h.cfg.Security.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", h.cfg.Server.Port)
	}

	now := time.Now()
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Sub:   userID,
		Nonce: nonce,
	}

	for _, scope := range scopes {
		switch scope {
		case "profile":
			if user, err := h.db.GetUser(userID); err == nil {
				claims.Name = user.Username
				claims.PreferredUsername = user.Username
			}
		case "email":
			if user, err := h.db.GetUser(userID); err == nil {
				claims.Email = user.Email
				claims.EmailVerified = user.Email != ""
			}
		}
	}

	key, kid := h.keySet.GetECKey()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid

	return token.SignedString(key)
}

func (h *Handler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.keySet.ToJWKS()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Authorization header required")
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
		return
	}

	at, err := h.db.GetAccessToken(tokenString)
	if err != nil {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Token not found")
		return
	}

	if at.Revoked || time.Now().After(at.ExpiresAt) {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Token expired or revoked")
		return
	}

	user, err := h.db.GetUser(at.UserID)
	if err != nil {
		writeOIDCError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	response := map[string]interface{}{
		"sub": user.ID,
	}

	for _, scope := range at.Scopes {
		switch scope {
		case "profile":
			response["name"] = user.Username
			response["preferred_username"] = user.Username
			response["given_name"] = ""
			response["family_name"] = ""
			response["picture"] = ""
			response["locale"] = "en"
			response["updated_at"] = user.CreatedAt.Unix()
		case "email":
			response["email"] = user.Email
			response["email_verified"] = user.Email != ""
		case "phone":
			response["phone_number"] = user.PhoneNumber
			response["phone_number_verified"] = user.PhoneNumber != ""
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.cfg.Security.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", h.cfg.Server.Port)
	}

	discovery := map[string]interface{}{
		"issuer":                                           issuer,
		"authorization_endpoint":                           issuer + "/oauth/authorize",
		"token_endpoint":                                   issuer + "/oauth/token",
		"userinfo_endpoint":                                issuer + "/oidc/userinfo",
		"jwks_uri":                                         issuer + "/oidc/jwks",
		"registration_endpoint":                            issuer + "/oauth/register",
		"revocation_endpoint":                              issuer + "/oauth/revoke",
		"introspection_endpoint":                           issuer + "/oauth/introspect",
		"device_authorization_endpoint":                    issuer + "/oauth/device",
		"pushed_authorization_request_endpoint":            issuer + "/oauth/par",
		"backchannel_authentication_endpoint":              issuer + "/oauth/bc-authorize",
		"scopes_supported":                                 h.cfg.OIDC.SupportedScopes,
		"response_types_supported":                         []string{"code"},
		"response_modes_supported":                         []string{"query", "fragment"},
		"grant_types_supported":                            h.cfg.OIDC.SupportedGrantTypes,
		"token_endpoint_auth_methods_supported":            h.cfg.OIDC.SupportedAuthMethods,
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "ES256"},
		"subject_types_supported":                          []string{"public"},
		"id_token_signing_alg_values_supported":            []string{"RS256", "ES256"},
		"code_challenge_methods_supported":                 []string{"S256", "plain"},
		"claims_supported":                                 h.cfg.OIDC.SupportedClaims,
		"claims_parameter_supported":                       true,
		"request_parameter_supported":                      true,
		"request_uri_parameter_supported":                  true,
		"require_pushed_authorization_requests":            false,
		"backchannel_token_delivery_modes_supported":       []string{"poll", "ping"},
		"backchannel_user_code_parameter_supported":        false,
		"dpop_signing_alg_values_supported":                []string{"ES256"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(discovery)
}

func (h *Handler) HandleASMetadata(w http.ResponseWriter, r *http.Request) {
	h.HandleDiscovery(w, r)
}

func writeOIDCError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, code, description))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func (h *Handler) GetKeySet() *KeySet {
	return h.keySet
}
