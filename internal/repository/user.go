package repository

import (
	"database/sql"
	"fmt"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
	query := `INSERT INTO users (id, username, password_hash, email, phone_number, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		user.ID, user.Username, user.PasswordHash,
		user.Email, user.PhoneNumber, user.CreatedAt,
	)
	return err
}

func (r *UserRepository) GetByID(id string) (*models.User, error) {
	query := `SELECT id, username, password_hash, email, phone_number, created_at
		FROM users WHERE id = ?`

	user := &models.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.Email, &user.PhoneNumber, &user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	query := `SELECT id, username, password_hash, email, phone_number, created_at
		FROM users WHERE username = ?`

	user := &models.User{}
	err := r.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.Email, &user.PhoneNumber, &user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) List() ([]*models.User, error) {
	query := `SELECT id, username, password_hash, email, phone_number, created_at
		FROM users ORDER BY created_at DESC`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]*models.User, 0)
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID, &user.Username, &user.PasswordHash,
			&user.Email, &user.PhoneNumber, &user.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (r *UserRepository) UpdateMFA(id string, mfaEnabled bool, mfaSecret string) error {
	query := `UPDATE users SET mfa_enabled = ?, mfa_secret = ?, mfa_pending_secret = NULL WHERE id = ?`
	_, err := r.db.Exec(query, mfaEnabled, mfaSecret, id)
	return err
}

func (r *UserRepository) GetMFA(id string) (bool, string, error) {
	query := `SELECT mfa_enabled, COALESCE(mfa_secret, '') FROM users WHERE id = ?`
	var mfaEnabled bool
	var mfaSecret string
	err := r.db.QueryRow(query, id).Scan(&mfaEnabled, &mfaSecret)
	return mfaEnabled, mfaSecret, err
}

func (r *UserRepository) SavePendingSecret(id string, secret string) error {
	query := `UPDATE users SET mfa_pending_secret = ? WHERE id = ?`
	_, err := r.db.Exec(query, secret, id)
	return err
}

func (r *UserRepository) GetPendingSecret(id string) (string, error) {
	query := `SELECT COALESCE(mfa_pending_secret, '') FROM users WHERE id = ?`
	var secret string
	err := r.db.QueryRow(query, id).Scan(&secret)
	if err != nil {
		return "", err
	}
	if secret == "" {
		return "", fmt.Errorf("no pending MFA secret found")
	}
	return secret, nil
}

func (r *UserRepository) ClearPendingSecret(id string) error {
	query := `UPDATE users SET mfa_pending_secret = NULL WHERE id = ?`
	_, err := r.db.Exec(query, id)
	return err
}
