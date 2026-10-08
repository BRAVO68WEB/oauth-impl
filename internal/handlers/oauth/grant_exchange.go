package oauth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func (h *Handler) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret := presentedClient(r)

	if clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client authentication required")
		return
	}

	client, ok := h.requireClient(w, clientID, "", http.StatusUnauthorized)
	if !ok {
		return
	}

	if authenticateClient(client, clientID, clientSecret, false) != "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	tokenType := boundTokenType(client)

	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")

	if subjectToken == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}

	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Unsupported subject_token_type: "+subjectTokenType)
		return
	}

	subjectTokenInfo, err := h.tokenRepo.GetAccessToken(subjectToken)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid subject_token")
		return
	}

	if subjectTokenInfo.Revoked || time.Now().After(subjectTokenInfo.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token is expired or revoked")
		return
	}

	scope := r.Form.Get("scope")
	scopes := crypto.NormalizeScopes(scope)
	if len(scopes) == 0 {
		scopes = subjectTokenInfo.Scopes
	}

	accessToken, err := h.issueAccessToken(clientID, subjectTokenInfo.UserID, strings.Join(scopes, " "), tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    subjectTokenInfo.UserID,
		Scopes:    scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":      accessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        tokenType,
		"expires_in":        int(h.cfg.Security.AccessTokenLifetime.Seconds()),
		"scope":             strings.Join(scopes, " "),
	})
}
