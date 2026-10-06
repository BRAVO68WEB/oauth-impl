package repository

import (
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"

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
	if token.ID == "" {
		token.ID = uuid.NewString()
	}
	if token.FamilyID == "" {
		token.FamilyID = uuid.NewString()
	}
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO refresh_tokens (id, token, access_token, client_id, user_id, scopes, family_id, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		token.ID, token.Token, token.AccessToken, token.ClientID,
		token.UserID, string(scopes), token.FamilyID, token.ExpiresAt, token.Revoked,
	)
	return err
}

func scanRefresh(scan func(dest ...any) error) (*models.RefreshToken, error) {
	rt := &models.RefreshToken{}
	var scopes string
	var id, family, userID sql.NullString
	if err := scan(
		&id, &rt.Token, &rt.AccessToken, &rt.ClientID,
		&userID, &scopes, &family, &rt.ExpiresAt, &rt.Revoked,
	); err != nil {
		return nil, err
	}
	rt.ID = id.String
	rt.FamilyID = family.String
	rt.UserID = userID.String
	if err := json.Unmarshal([]byte(scopes), &rt.Scopes); err != nil {
		return nil, err
	}
	return rt, nil
}

const refreshColumns = `COALESCE(id, ''), token, COALESCE(access_token, ''), client_id, user_id, scopes, COALESCE(family_id, ''), expires_at, revoked`

func (r *TokenRepository) GetRefreshToken(token string) (*models.RefreshToken, error) {
	return scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE token = ?`, token).Scan)
}

func (r *TokenRepository) GetRefreshByID(id string) (*models.RefreshToken, error) {
	return scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE id = ?`, id).Scan)
}

func (r *TokenRepository) RevokeRefreshToken(token string) error {
	_, err := r.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", token)
	return err
}

func (r *TokenRepository) GetRefreshTokenByAccessToken(accessToken string) (*models.RefreshToken, error) {
	return scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE access_token = ?`, accessToken).Scan)
}

func (r *TokenRepository) RevokeFamily(familyID string) error {
	if familyID == "" {
		return nil
	}
	rows, err := r.db.Query(`SELECT access_token FROM refresh_tokens WHERE family_id = ? AND access_token IS NOT NULL AND access_token != ''`, familyID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var access []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return err
		}
		access = append(access, token)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, token := range access {
		if _, err := r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE token = ?`, token); err != nil {
			return err
		}
	}
	_, err = r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, familyID)
	return err
}

func (r *TokenRepository) ListRefreshTokens(clientID, userID string) ([]*models.RefreshToken, error) {
	query := `SELECT ` + refreshColumns + ` FROM refresh_tokens WHERE 1=1`
	args := []any{}
	if clientID != "" {
		query += ` AND client_id = ?`
		args = append(args, clientID)
	}
	if userID != "" {
		query += ` AND user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY expires_at DESC`
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]*models.RefreshToken, 0)
	for rows.Next() {
		rt, err := scanRefresh(rows.Scan)
		if err != nil {
			return nil, err
		}
		rt.Token = ""
		rt.AccessToken = ""
		out = append(out, rt)
	}
	return out, rows.Err()
}

func (r *TokenRepository) RevokeAllForUser(userID string) error {
	_, _ = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	_, err := r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	return err
}

func (r *TokenRepository) RevokeOtherFamilies(userID, keepAccessToken string) error {
	keepFamily := ""
	if keepAccessToken != "" {
		if rt, err := r.GetRefreshTokenByAccessToken(keepAccessToken); err == nil {
			keepFamily = rt.FamilyID
		}
	}
	rows, err := r.db.Query(`SELECT COALESCE(family_id, ''), COALESCE(access_token, '') FROM refresh_tokens WHERE user_id = ? AND revoked = 0`, userID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	type pair struct{ family, access string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.family, &p.access); err != nil {
			return err
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range pairs {
		if keepFamily != "" && p.family == keepFamily {
			continue
		}
		if p.access != "" && p.access != keepAccessToken {
			_, _ = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE token = ?`, p.access)
		}
		if p.family != "" {
			_, _ = r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, p.family)
		}
	}
	if keepAccessToken != "" {
		_, err = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE user_id = ? AND token != ?`, userID, keepAccessToken)
	} else {
		_, err = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	}
	return err
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
