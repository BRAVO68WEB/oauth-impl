package controller

import (
	"errors"
	"net/http"

	"github.com/bravo68web/oauth-impl/internal/auth"
	"github.com/bravo68web/oauth-impl/internal/service"
)

func issueCSRF(w http.ResponseWriter, r *http.Request, secure bool) string {
	return service.IssueCSRF(w, r, secure)
}

func csrfOK(r *http.Request) bool {
	return service.CSRFMatch(r)
}

func rejectCSRF(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "csrf_failed", "CSRF token is missing or invalid")
}

func writePassword(w http.ResponseWriter, err error) bool {
	var pe *service.PasswordError
	if errors.As(err, &pe) {
		writeError(w, http.StatusBadRequest, "invalid_password", pe.Error())
		return true
	}
	return false
}

func (c *ManagementController) writeAudit(r *http.Request, action, targetType, targetID string, meta map[string]any) {
	if c == nil || c.audit == nil {
		return
	}
	actor := "unknown"
	if tok := auth.TokenFrom(r.Context()); tok != nil && tok.ClientID != "" {
		actor = tok.ClientID
	}
	c.audit.Write("client", actor, action, targetType, targetID, r, meta)
}
