package repository

import (
	"database/sql"
	"encoding/json"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type AuthCodeRepository struct {
	db *sql.DB
}

func NewAuthCodeRepository(db *sql.DB) *AuthCodeRepository {
	return &AuthCodeRepository{db: db}
}

func (r *AuthCodeRepository) Save(code *models.AuthorizationCode) error {
	scopes, _ := json.Marshal(code.Scopes)
	query := `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes,
		code_challenge, code_challenge_method, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		code.Code, code.ClientID, code.UserID, code.RedirectURI,
		string(scopes), code.CodeChallenge, code.CodeChallengeMethod,
		code.ExpiresAt, code.Used,
	)
	return err
}

func (r *AuthCodeRepository) Get(code string) (*models.AuthorizationCode, error) {
	query := `SELECT code, client_id, user_id, redirect_uri, scopes,
		code_challenge, code_challenge_method, expires_at, used
		FROM authorization_codes WHERE code = ?`

	ac := &models.AuthorizationCode{}
	var scopes string

	err := r.db.QueryRow(query, code).Scan(
		&ac.Code, &ac.ClientID, &ac.UserID, &ac.RedirectURI,
		&scopes, &ac.CodeChallenge, &ac.CodeChallengeMethod,
		&ac.ExpiresAt, &ac.Used,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &ac.Scopes); err != nil {
		return nil, err
	}
	return ac, nil
}

func (r *AuthCodeRepository) MarkUsed(code string) error {
	_, err := r.db.Exec("UPDATE authorization_codes SET used = 1 WHERE code = ?", code)
	return err
}
