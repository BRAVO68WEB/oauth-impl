package repository

import (
	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type DPoPRepository struct {
	db database.SQL
}

func NewDPoPRepository(db database.SQL) *DPoPRepository {
	return &DPoPRepository{db: db}
}

func (r *DPoPRepository) Save(proof *models.DPoPProof) error {
	query := `INSERT INTO dpop_proofs (jti, htm, htu, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		proof.JTI, proof.HTM, proof.HTU, proof.CreatedAt, proof.ExpiresAt,
	)
	return err
}

func (r *DPoPRepository) GetByJTI(jti string) (*models.DPoPProof, error) {
	query := `SELECT jti, htm, htu, created_at, expires_at
		FROM dpop_proofs WHERE jti = ?`

	proof := &models.DPoPProof{}
	err := r.db.QueryRow(query, jti).Scan(
		&proof.JTI, &proof.HTM, &proof.HTU, &proof.CreatedAt, &proof.ExpiresAt,
	)
	return proof, err
}
