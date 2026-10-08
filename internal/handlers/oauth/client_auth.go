package oauth

import (
	"net/http"

	"github.com/bravo68web/oauth-impl/internal/models"
)

func presentedClient(r *http.Request) (string, string) {
	id, secret, ok := r.BasicAuth()
	if ok {
		return id, secret
	}
	return r.Form.Get("client_id"), r.Form.Get("client_secret")
}

// authenticateClient checks presented credentials against client.
// token_endpoint_auth_method none succeeds without a secret.
// matchID is set when client was loaded from a stored grant, not from the presented id.
// The result is empty on success, or mismatch, missing_secret, or bad_secret.
func authenticateClient(client *models.Client, presentedID, presentedSecret string, matchID bool) string {
	if client == nil {
		return "bad_secret"
	}
	if client.TokenEndpointAuthMethod == "none" {
		return ""
	}
	if matchID && presentedID != client.ID {
		return "mismatch"
	}
	if presentedSecret == "" {
		return "missing_secret"
	}
	if presentedSecret != client.Secret {
		return "bad_secret"
	}
	return ""
}
