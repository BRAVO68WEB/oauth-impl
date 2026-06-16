package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

type TokenService struct {
	tokenRepo *repository.TokenRepository
	authRepo  *repository.AuthCodeRepository
	oidcSvc   *oidc.Handler
	cfg       *config.SecurityConfig
}

type TokenResult struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int
	Scope        string
}

func NewTokenService(tokenRepo *repository.TokenRepository, authRepo *repository.AuthCodeRepository, oidcSvc *oidc.Handler, cfg *config.SecurityConfig) *TokenService {
	return &TokenService{
		tokenRepo: tokenRepo,
		authRepo:  authRepo,
		oidcSvc:   oidcSvc,
		cfg:       cfg,
	}
}

func (s *TokenService) GenerateClientCredentialsToken(clientID string, scopes []string) (*TokenResult, error) {
	accessToken, err := crypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scopes:    scopes,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(s.cfg.AccessTokenLifetime),
	}

	if err := s.tokenRepo.SaveAccessToken(accessTok); err != nil {
		return nil, fmt.Errorf("failed to save access token: %w", err)
	}

	return &TokenResult{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.cfg.AccessTokenLifetime.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

func (s *TokenService) GenerateAuthorizationCodeToken(clientID, userID, code, redirectURI, codeVerifier string, scopes []string) (*TokenResult, error) {
	authCode, err := s.authRepo.Get(code)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code")
	}

	if authCode.Used {
		return nil, fmt.Errorf("authorization code already used")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}

	if redirectURI != "" && redirectURI != authCode.RedirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch")
	}

	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, fmt.Errorf("code_verifier is required")
		}
		if !crypto.ValidateCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, fmt.Errorf("invalid code_verifier")
		}
	}

	if err := s.authRepo.MarkUsed(code); err != nil {
		return nil, fmt.Errorf("failed to mark authorization code as used: %w", err)
	}

	accessToken, err := crypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(s.cfg.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    clientID,
		UserID:      userID,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(s.cfg.RefreshTokenLifetime),
	}

	if err := s.tokenRepo.SaveAccessToken(accessTok); err != nil {
		return nil, fmt.Errorf("failed to save access token: %w", err)
	}

	if err := s.tokenRepo.SaveRefreshToken(refreshTok); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	var idToken string
	if containsScope(scopes, "openid") && s.oidcSvc != nil {
		idToken, err = s.oidcSvc.CreateIDToken(clientID, userID, "", scopes)
		if err != nil {
			return nil, fmt.Errorf("failed to create ID token: %w", err)
		}
	}

	return &TokenResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.AccessTokenLifetime.Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

func (s *TokenService) IntrospectToken(token string) (map[string]interface{}, error) {
	at, err := s.tokenRepo.GetAccessToken(token)
	if err != nil {
		return map[string]interface{}{"active": false}, nil
	}

	if at.Revoked || time.Now().After(at.ExpiresAt) {
		return map[string]interface{}{"active": false}, nil
	}

	response := map[string]interface{}{
		"active":     true,
		"scope":      strings.Join(at.Scopes, " "),
		"client_id":  at.ClientID,
		"token_type": at.TokenType,
		"exp":        at.ExpiresAt.Unix(),
		"iat":        at.ExpiresAt.Add(-s.cfg.AccessTokenLifetime).Unix(),
	}

	if at.UserID != "" {
		response["sub"] = at.UserID
	}

	return response, nil
}

func (s *TokenService) RevokeToken(token string) error {
	return s.tokenRepo.RevokeAccessToken(token)
}

func (s *TokenService) ListTokens(clientID, userID string) ([]*models.AccessToken, error) {
	return s.tokenRepo.ListAccessTokens(clientID, userID)
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
