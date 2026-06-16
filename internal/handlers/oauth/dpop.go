package oauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func (h *Handler) ValidateDPoPProof(r *http.Request, accessToken string) error {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return fmt.Errorf("DPoP header is required")
	}

	// Build full URI for DPoP validation
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fullURI := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)

	_, err := h.dpopSvc.ValidateDPoPProof(dpopHeader, r.Method, fullURI, accessToken)
	if err != nil {
		return err
	}

	return nil
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

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(refreshTok); err != nil {
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

	jkt, err := h.dpopSvc.GetJKTFromProof(dpopHeader)
	if err != nil {
		return "", err
	}

	return jkt, nil
}
