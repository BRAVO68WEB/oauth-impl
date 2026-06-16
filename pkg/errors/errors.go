package errors

import (
	"fmt"
	"net/http"
)

type OAuthErrorCode string

const (
	ErrInvalidRequest       OAuthErrorCode = "invalid_request"
	ErrInvalidClient        OAuthErrorCode = "invalid_client"
	ErrInvalidGrant         OAuthErrorCode = "invalid_grant"
	ErrUnauthorizedClient   OAuthErrorCode = "unauthorized_client"
	ErrUnsupportedGrantType OAuthErrorCode = "unsupported_grant_type"
	ErrInvalidScope         OAuthErrorCode = "invalid_scope"
	ErrAccessDenied         OAuthErrorCode = "access_denied"
	ErrServerError          OAuthErrorCode = "server_error"
	ErrInvalidToken         OAuthErrorCode = "invalid_token"
	ErrInvalidDPoPProof     OAuthErrorCode = "invalid_dpop_proof"
	ErrExpiredToken         OAuthErrorCode = "expired_token"
	ErrAuthorizationPending OAuthErrorCode = "authorization_pending"
	ErrSlowDown             OAuthErrorCode = "slow_down"
	ErrInvalidRedirectURI   OAuthErrorCode = "invalid_redirect_uri"
)

type OAuthError struct {
	Code        OAuthErrorCode `json:"error"`
	Description string         `json:"error_description,omitempty"`
	URI         string         `json:"error_uri,omitempty"`
	State       string         `json:"state,omitempty"`
	StatusCode  int            `json:"-"`
}

func (e *OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func NewOAuthError(code OAuthErrorCode, description string) *OAuthError {
	return &OAuthError{
		Code:        code,
		Description: description,
		StatusCode:  codeToStatus(code),
	}
}

func NewOAuthErrorWithState(code OAuthErrorCode, description, state string) *OAuthError {
	return &OAuthError{
		Code:        code,
		Description: description,
		State:       state,
		StatusCode:  codeToStatus(code),
	}
}

func codeToStatus(code OAuthErrorCode) int {
	switch code {
	case ErrInvalidRequest:
		return http.StatusBadRequest
	case ErrInvalidClient:
		return http.StatusUnauthorized
	case ErrInvalidGrant:
		return http.StatusBadRequest
	case ErrUnauthorizedClient:
		return http.StatusForbidden
	case ErrUnsupportedGrantType:
		return http.StatusBadRequest
	case ErrInvalidScope:
		return http.StatusBadRequest
	case ErrAccessDenied:
		return http.StatusForbidden
	case ErrServerError:
		return http.StatusInternalServerError
	case ErrInvalidToken:
		return http.StatusUnauthorized
	case ErrInvalidDPoPProof:
		return http.StatusBadRequest
	case ErrExpiredToken:
		return http.StatusBadRequest
	case ErrAuthorizationPending:
		return http.StatusBadRequest
	case ErrSlowDown:
		return http.StatusBadRequest
	case ErrInvalidRedirectURI:
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

func InvalidRequest(description string) *OAuthError {
	return NewOAuthError(ErrInvalidRequest, description)
}

func InvalidClient(description string) *OAuthError {
	return NewOAuthError(ErrInvalidClient, description)
}

func InvalidGrant(description string) *OAuthError {
	return NewOAuthError(ErrInvalidGrant, description)
}

func UnauthorizedClient(description string) *OAuthError {
	return NewOAuthError(ErrUnauthorizedClient, description)
}

func UnsupportedGrantType(description string) *OAuthError {
	return NewOAuthError(ErrUnsupportedGrantType, description)
}

func ServerError(description string) *OAuthError {
	return NewOAuthError(ErrServerError, description)
}

func InvalidToken(description string) *OAuthError {
	return NewOAuthError(ErrInvalidToken, description)
}

func ExpiredToken(description string) *OAuthError {
	return NewOAuthError(ErrExpiredToken, description)
}

func AuthorizationPending(description string) *OAuthError {
	return NewOAuthError(ErrAuthorizationPending, description)
}

func AccessDenied(description string) *OAuthError {
	return NewOAuthError(ErrAccessDenied, description)
}
