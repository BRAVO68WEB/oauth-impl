package repository

import (
	"database/sql"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type NonceRepository struct {
	db *sql.DB
}

func NewNonceRepository(db *sql.DB) *NonceRepository {
	return &NonceRepository{db: db}
}

func (r *NonceRepository) Save(nonce *models.OIDCNonce) error {
	query := `INSERT INTO oidc_nonces (nonce, client_id, expires_at) VALUES (?, ?, ?)`

	_, err := r.db.Exec(query, nonce.Nonce, nonce.ClientID, nonce.ExpiresAt)
	return err
}

func (r *NonceRepository) Get(nonce string) (*models.OIDCNonce, error) {
	query := `SELECT nonce, client_id, expires_at FROM oidc_nonces WHERE nonce = ?`

	n := &models.OIDCNonce{}
	err := r.db.QueryRow(query, nonce).Scan(&n.Nonce, &n.ClientID, &n.ExpiresAt)
	return n, err
}
