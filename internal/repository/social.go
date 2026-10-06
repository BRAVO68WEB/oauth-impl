package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type SocialLogin struct {
	State     string
	Provider  string
	Verifier  string
	Nonce     string
	Params    map[string]string
	ExpiresAt time.Time
	Used      bool
}

type SocialRepository struct {
	db *sql.DB
}

func NewSocialRepository(db *sql.DB) *SocialRepository {
	return &SocialRepository{db: db}
}

func (r *SocialRepository) SaveLogin(row SocialLogin) error {
	raw, err := json.Marshal(row.Params)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO social_logins (state, provider, verifier, nonce, params_json, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, 0)`,
		row.State, row.Provider, row.Verifier, row.Nonce, string(raw), row.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

// Consume marks a login row used and returns it. A missing, used, or other-provider state returns sql.ErrNoRows.
func (r *SocialRepository) Consume(state, provider string) (SocialLogin, error) {
	res, err := r.db.Exec(`UPDATE social_logins SET used = 1 WHERE state = ? AND provider = ? AND used = 0`, state, provider)
	if err != nil {
		return SocialLogin{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return SocialLogin{}, err
	}
	if n == 0 {
		return SocialLogin{}, sql.ErrNoRows
	}
	var raw, exp string
	row := SocialLogin{Params: map[string]string{}}
	err = r.db.QueryRow(`SELECT state, provider, verifier, nonce, params_json, expires_at, used FROM social_logins WHERE state = ?`, state).
		Scan(&row.State, &row.Provider, &row.Verifier, &row.Nonce, &raw, &exp, &row.Used)
	if err != nil {
		return SocialLogin{}, err
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &row.Params); err != nil {
			return SocialLogin{}, err
		}
	}
	row.ExpiresAt, err = time.Parse(time.RFC3339, exp)
	if err != nil {
		return SocialLogin{}, err
	}
	return row, nil
}

func (r *SocialRepository) FindIdentity(provider, subject string) (string, error) {
	var userID string
	err := r.db.QueryRow(`SELECT user_id FROM social_identities WHERE provider = ? AND subject = ?`, provider, subject).Scan(&userID)
	return userID, err
}

func (r *SocialRepository) InsertIdentity(provider, subject, userID, email string, created time.Time) error {
	_, err := r.db.Exec(`INSERT INTO social_identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)`,
		provider, subject, userID, email, created.UTC().Format(time.RFC3339))
	return err
}

func IsNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
