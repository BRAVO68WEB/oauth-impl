package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type KeyPair struct {
	PrivateKey interface{}
	PublicKey  interface{}
	Algorithm  string
}

func GenerateRSAKeyPair(bits int) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  "RS256",
	}, nil
}

func GenerateECKeyPair(curve elliptic.Curve) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC key: %w", err)
	}

	alg := "ES256"
	switch curve {
	case elliptic.P384():
		alg = "ES384"
	case elliptic.P521():
		alg = "ES512"
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  alg,
	}, nil
}

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Scope    string   `json:"scope,omitempty"`
	ClientID string   `json:"client_id"`
	TokenType string  `json:"token_type,omitempty"`
	DPoPJKT  string   `json:"dpop_jkt,omitempty"`
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce               string `json:"nonce,omitempty"`
	AuthTime            int64  `json:"auth_time,omitempty"`
	AtHash              string `json:"at_hash,omitempty"`
	Name                string `json:"name,omitempty"`
	GivenName           string `json:"given_name,omitempty"`
	FamilyName          string `json:"family_name,omitempty"`
	PreferredUsername   string `json:"preferred_username,omitempty"`
	Email               string `json:"email,omitempty"`
	EmailVerified       bool   `json:"email_verified,omitempty"`
	Picture             string `json:"picture,omitempty"`
}

type ClientAssertionClaims struct {
	jwt.RegisteredClaims
}

func CreateAccessToken(issuer, clientID, userID string, scopes []string, lifetime time.Duration, keyPair *KeyPair) (string, error) {
	now := time.Now()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{issuer},
			ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        mustGenerateID(),
		},
		Scope:     joinScopes(scopes),
		ClientID:  clientID,
		TokenType: "Bearer",
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(keyPair.Algorithm), claims)
	switch k := keyPair.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return token.SignedString(k)
	case *ecdsa.PrivateKey:
		return token.SignedString(k)
	default:
		return "", fmt.Errorf("unsupported key type")
	}
}

func CreateIDToken(issuer, clientID, userID string, nonce string, lifetime time.Duration, keyPair *KeyPair) (string, error) {
	now := time.Now()
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(lifetime)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Nonce: nonce,
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(keyPair.Algorithm), claims)
	switch k := keyPair.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return token.SignedString(k)
	case *ecdsa.PrivateKey:
		return token.SignedString(k)
	default:
		return "", fmt.Errorf("unsupported key type")
	}
}

func ValidateToken(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.Parse(tokenString, keyFunc)
}

func ValidateAccessToken(tokenString string, publicKey interface{}) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			return publicKey.(*rsa.PublicKey), nil
		case *jwt.SigningMethodECDSA:
			return publicKey.(*ecdsa.PublicKey), nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AccessTokenClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token claims")
}

func mustGenerateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a simple ID if random generation fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}
