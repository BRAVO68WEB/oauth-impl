package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

type DPoPValidator struct {
	usedJTIs map[string]time.Time
}

func NewDPoPValidator() *DPoPValidator {
	return &DPoPValidator{
		usedJTIs: make(map[string]time.Time),
	}
}

func (v *DPoPValidator) ValidateProof(r *http.Request, accessToken string) (*DPoPClaims, error) {
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
			return parseECKey(jwk)
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

	if err := v.validateClaims(claims, r); err != nil {
		return nil, err
	}

	if accessToken != "" {
		if err := validateATH(claims.ATH, accessToken); err != nil {
			return nil, err
		}
	}

	return claims, nil
}

func parseECKey(jwk DPoPJWK) (*ecdsa.PublicKey, error) {
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

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (v *DPoPValidator) validateClaims(claims *DPoPClaims, r *http.Request) error {
	if claims.HTM != r.Method {
		return fmt.Errorf("htm mismatch: expected %s, got %s", r.Method, claims.HTM)
	}

	expectedHTU := fmt.Sprintf("%s://%s%s", "http", r.Host, r.URL.Path)
	if r.TLS != nil {
		expectedHTU = fmt.Sprintf("%s://%s%s", "https", r.Host, r.URL.Path)
	}
	if claims.HTU != expectedHTU {
		return fmt.Errorf("htu mismatch: expected %s, got %s", expectedHTU, claims.HTU)
	}

	if time.Since(claims.IssuedAt.Time) > 5*time.Minute {
		return fmt.Errorf("DPoP proof expired")
	}

	if _, exists := v.usedJTIs[claims.JTI]; exists {
		return fmt.Errorf("DPoP proof replay detected")
	}

	v.usedJTIs[claims.JTI] = time.Now()
	v.cleanupOldJTIs()

	return nil
}

func validateATH(ath, accessToken string) error {
	hash := sha256.Sum256([]byte(accessToken))
	expectedATH := base64.RawURLEncoding.EncodeToString(hash[:])
	if ath != expectedATH {
		return fmt.Errorf("ath mismatch")
	}
	return nil
}

func (v *DPoPValidator) cleanupOldJTIs() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for jti, t := range v.usedJTIs {
		if t.Before(cutoff) {
			delete(v.usedJTIs, jti)
		}
	}
}

func ExtractJWKTumbprint(dpopHeader string) (string, error) {
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
