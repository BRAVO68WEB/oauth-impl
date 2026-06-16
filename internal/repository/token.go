package repository

import (
	"database/sql"
	"encoding/json"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type TokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) SaveAccessToken(token *models.AccessToken) error {
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO access_tokens (token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		token.Token, token.ClientID, token.UserID,
		string(scopes), token.TokenType, token.DPoPJKT,
		token.ExpiresAt, token.Revoked,
	)
	return err
}

func (r *TokenRepository) GetAccessToken(token string) (*models.AccessToken, error) {
	query := `SELECT token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked
		FROM access_tokens WHERE token = ?`

	at := &models.AccessToken{}
	var scopes string

	err := r.db.QueryRow(query, token).Scan(
		&at.Token, &at.ClientID, &at.UserID,
		&scopes, &at.TokenType, &at.DPoPJKT,
		&at.ExpiresAt, &at.Revoked,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &at.Scopes); err != nil {
		return nil, err
	}
	return at, nil
}

func (r *TokenRepository) RevokeAccessToken(token string) error {
	_, err := r.db.Exec("UPDATE access_tokens SET revoked = 1 WHERE token = ?", token)
	return err
}

func (r *TokenRepository) SaveRefreshToken(token *models.RefreshToken) error {
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO refresh_tokens (token, access_token, client_id, user_id, scopes, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		token.Token, token.AccessToken, token.ClientID,
		token.UserID, string(scopes), token.ExpiresAt, token.Revoked,
	)
	return err
}

func (r *TokenRepository) GetRefreshToken(token string) (*models.RefreshToken, error) {
	query := `SELECT token, access_token, client_id, user_id, scopes, expires_at, revoked
		FROM refresh_tokens WHERE token = ?`

	rt := &models.RefreshToken{}
	var scopes string

	err := r.db.QueryRow(query, token).Scan(
		&rt.Token, &rt.AccessToken, &rt.ClientID,
		&rt.UserID, &scopes, &rt.ExpiresAt, &rt.Revoked,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &rt.Scopes); err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *TokenRepository) RevokeRefreshToken(token string) error {
	_, err := r.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", token)
	return err
}

func (r *TokenRepository) GetRefreshTokenByAccessToken(accessToken string) (*models.RefreshToken, error) {
	query := `SELECT token, access_token, client_id, user_id, scopes, expires_at, revoked
		FROM refresh_tokens WHERE access_token = ?`

	rt := &models.RefreshToken{}
	var scopes string

	err := r.db.QueryRow(query, accessToken).Scan(
		&rt.Token, &rt.AccessToken, &rt.ClientID,
		&rt.UserID, &scopes, &rt.ExpiresAt, &rt.Revoked,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &rt.Scopes); err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *TokenRepository) RevokeAllForClient(clientID, userID string) error {
	_, _ = r.db.Exec("UPDATE access_tokens SET revoked = 1 WHERE client_id = ? AND user_id = ?", clientID, userID)
	_, _ = r.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE client_id = ? AND user_id = ?", clientID, userID)
	return nil
}

func (r *TokenRepository) ListAccessTokens(clientID, userID string) ([]*models.AccessToken, error) {
	query := `SELECT token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked
		FROM access_tokens WHERE 1=1`
	args := []interface{}{}

	if clientID != "" {
		query += " AND client_id = ?"
		args = append(args, clientID)
	}
	if userID != "" {
		query += " AND user_id = ?"
		args = append(args, userID)
	}
	query += " ORDER BY expires_at DESC"

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	tokens := make([]*models.AccessToken, 0)
	for rows.Next() {
		at := &models.AccessToken{}
		var scopes string
		err := rows.Scan(
			&at.Token, &at.ClientID, &at.UserID,
			&scopes, &at.TokenType, &at.DPoPJKT,
			&at.ExpiresAt, &at.Revoked,
		)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &at.Scopes); err != nil {
			return nil, err
		}
		tokens = append(tokens, at)
	}
	return tokens, nil
}
