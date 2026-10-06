package oauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

// enforceClientDPoP requires a proof when the OAuth app forces DPoP.
// The server flag security.dpop.enabled does not turn this off.
// The bool is false when the error response has already been written.
func (h *Handler) enforceClientDPoP(w http.ResponseWriter, r *http.Request, client *models.Client) (string, bool) {
	if client == nil || !client.DPoPBoundAccessTokens {
		return "", true
	}
	if err := h.ValidateDPoPProof(r, ""); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
		return "", false
	}
	jkt, err := h.GetDPoPJKT(r)
	if err != nil || jkt == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", "Failed to get JKT")
		return "", false
	}
	return jkt, true
}

func (h *Handler) revokeDPoP(w http.ResponseWriter, r *http.Request, client *models.Client, token string) bool {
	needs := client != nil && client.DPoPBoundAccessTokens
	proofToken := ""
	if at, err := h.tokenRepo.GetAccessToken(token); err == nil && (at.TokenType == "DPoP" || at.DPoPJKT != "") {
		needs = true
		proofToken = at.Token
	} else if rt, err := h.tokenRepo.GetRefreshToken(token); err == nil && rt.AccessToken != "" {
		if at, err := h.tokenRepo.GetAccessToken(rt.AccessToken); err == nil && (at.TokenType == "DPoP" || at.DPoPJKT != "") {
			needs = true
			proofToken = at.Token
		}
	}
	if !needs {
		return true
	}
	if err := h.ValidateDPoPProof(r, proofToken); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_token", err.Error())
		return false
	}
	return true
}

func boundTokenType(client *models.Client) string {
	if client != nil && client.DPoPBoundAccessTokens {
		return "DPoP"
	}
	return "Bearer"
}

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
	accessToken, err := h.issueAccessToken(clientID, userID, strings.Join(scopes, " "), "DPoP")
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
