package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

type DPoPClaims struct {
	jwt.RegisteredClaims
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	ATH string `json:"ath,omitempty"`
}

type DPoPJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
}

func (h *Handler) ValidateDPoPProof(r *http.Request, accessToken string) (*DPoPClaims, error) {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return nil, fmt.Errorf("DPoP header is required")
	}

	token, err := jwt.ParseWithClaims(dpopHeader, &DPoPClaims{}, func(token *jwt.Token) (interface{}, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("missing alg header")
		}

		if alg != "ES256" && alg != "RS256" {
			return nil, fmt.Errorf("unsupported algorithm: %s", alg)
		}

		jwkRaw, ok := token.Header["jwk"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("missing jwk header")
		}

		jwkJSON, err := json.Marshal(jwkRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal jwk")
		}

		var jwk DPoPJWK
		if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
			return nil, fmt.Errorf("failed to parse jwk")
		}

		if jwk.Kty == "EC" {
			xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil {
				return nil, fmt.Errorf("failed to decode x")
			}
			yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
			if err != nil {
				return nil, fmt.Errorf("failed to decode y")
			}

			curve := elliptic.P256()
			if jwk.Crv == "P-384" {
				curve = elliptic.P384()
			} else if jwk.Crv == "P-521" {
				curve = elliptic.P521()
			}

			x := new(big.Int).SetBytes(xBytes)
			y := new(big.Int).SetBytes(yBytes)

			pubKey := &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			}

			return pubKey, nil
		}

		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	})

	if err != nil {
		return nil, fmt.Errorf("invalid DPoP proof: %w", err)
	}

	claims, ok := token.Claims.(*DPoPClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid DPoP claims")
	}

	if claims.HTM != r.Method {
		return nil, fmt.Errorf("htm mismatch: expected %s, got %s", r.Method, claims.HTM)
	}

	expectedHTU := fmt.Sprintf("%s://%s%s", "http", r.Host, r.URL.Path)
	if r.TLS != nil {
		expectedHTU = fmt.Sprintf("%s://%s%s", "https", r.Host, r.URL.Path)
	}
	if claims.HTU != expectedHTU {
		return nil, fmt.Errorf("htu mismatch: expected %s, got %s", expectedHTU, claims.HTU)
	}

	if time.Since(claims.IssuedAt.Time) > 5*time.Minute {
		return nil, fmt.Errorf("DPoP proof expired")
	}

	if existing, err := h.db.GetDPoPProof(claims.JTI); err == nil && existing != nil {
		return nil, fmt.Errorf("DPoP proof replay detected")
	}

	proof := &models.DPoPProof{
		JTI:       claims.JTI,
		HTM:       claims.HTM,
		HTU:       claims.HTU,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	// Save DPoP proof (best effort, ignore errors)
	_ = h.db.SaveDPoPProof(proof)

	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		expectedATH := base64.RawURLEncoding.EncodeToString(hash[:])
		if claims.ATH != expectedATH {
			return nil, fmt.Errorf("ath mismatch")
		}
	}

	return claims, nil
}

func (h *Handler) GenerateDPoPBoundToken(w http.ResponseWriter, r *http.Request, clientID, userID string, scopes []string, dpopJKT string) {
	accessToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		TokenType: "DPoP",
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    clientID,
		UserID:      userID,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(h.cfg.Security.RefreshTokenLifetime),
	}

	if err := h.db.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.db.SaveRefreshToken(refreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	writeTokenResponse(w, accessToken, refreshToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), "DPoP", strings.Join(scopes, " "))
}

func (h *Handler) GetDPoPJKT(r *http.Request) (string, error) {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return "", nil
	}

	token, _, err := new(jwt.Parser).ParseUnverified(dpopHeader, &DPoPClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse DPoP proof: %w", err)
	}

	jwkRaw, ok := token.Header["jwk"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing jwk header")
	}

	jwkJSON, err := json.Marshal(jwkRaw)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jwk")
	}

	var jwk DPoPJWK
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return "", fmt.Errorf("failed to parse jwk")
	}

	if jwk.Kty != "EC" {
		return "", fmt.Errorf("unsupported key type")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return "", fmt.Errorf("failed to decode x")
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return "", fmt.Errorf("failed to decode y")
	}

	thumbprint := sha256.Sum256(append(xBytes, yBytes...))
	return base64.RawURLEncoding.EncodeToString(thumbprint[:]), nil
}
