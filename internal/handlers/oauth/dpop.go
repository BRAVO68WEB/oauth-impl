package oauth

import (
	"fmt"
	"net/http"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/service"
)

// enforceClientDPoP requires a proof when the OAuth app forces DPoP.
// The server flag security.dpop.enabled does not turn this off.
// The bool is false when the error response has already been written.
func (h *Handler) enforceClientDPoP(w http.ResponseWriter, r *http.Request, client *models.Client) (string, bool) {
	if client == nil || !client.DPoPBoundAccessTokens {
		return "", true
	}
	proof, err := h.ValidateDPoPProof(r, "")
	if err != nil || proof == nil || proof.JKT == "" {
		desc := "Failed to get JKT"
		if err != nil {
			desc = err.Error()
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", desc)
		return "", false
	}
	return proof.JKT, true
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
	if _, err := h.ValidateDPoPProof(r, proofToken); err != nil {
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

func (h *Handler) ValidateDPoPProof(r *http.Request, accessToken string) (*service.DPoPProof, error) {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return nil, fmt.Errorf("DPoP header is required")
	}

	// Build full URI for DPoP validation
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fullURI := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)

	return h.dpopSvc.ValidateDPoPProof(dpopHeader, r.Method, fullURI, accessToken)
}
