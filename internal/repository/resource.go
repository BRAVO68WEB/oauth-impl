package repository

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type ResourceRepository struct {
	db *sql.DB
}

func NewResourceRepository(db *sql.DB) *ResourceRepository {
	return &ResourceRepository{db: db}
}

func (r *ResourceRepository) Create(resource *models.Resource) error {
	scopesJSON, err := json.Marshal(resource.Scopes)
	if err != nil {
		return err
	}

	query := `INSERT INTO resources (uri, name, description, scopes, created_at)
		VALUES (?, ?, ?, ?, ?)`

	_, err = r.db.Exec(query,
		resource.URI, resource.Name, resource.Description,
		string(scopesJSON), time.Now(),
	)
	return err
}

func (r *ResourceRepository) Get(uri string) (*models.Resource, error) {
	query := `SELECT uri, name, description, scopes, created_at
		FROM resources WHERE uri = ?`

	resource := &models.Resource{}
	var scopesStr string

	err := r.db.QueryRow(query, uri).Scan(
		&resource.URI, &resource.Name, &resource.Description,
		&scopesStr, &resource.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if scopesStr != "" {
		if err := json.Unmarshal([]byte(scopesStr), &resource.Scopes); err != nil {
			resource.Scopes = []string{}
		}
	}

	return resource, nil
}

func (r *ResourceRepository) List() ([]*models.Resource, error) {
	query := `SELECT uri, name, description, scopes, created_at
		FROM resources ORDER BY name`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	resources := make([]*models.Resource, 0)
	for rows.Next() {
		resource := &models.Resource{}
		var scopesStr string

		err := rows.Scan(
			&resource.URI, &resource.Name, &resource.Description,
			&scopesStr, &resource.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if scopesStr != "" {
			if err := json.Unmarshal([]byte(scopesStr), &resource.Scopes); err != nil {
				resource.Scopes = []string{}
			}
		}

		resources = append(resources, resource)
	}
	return resources, nil
}

func (r *ResourceRepository) Update(resource *models.Resource) error {
	scopesJSON, err := json.Marshal(resource.Scopes)
	if err != nil {
		return err
	}

	query := `UPDATE resources SET name = ?, description = ?, scopes = ? WHERE uri = ?`

	_, err = r.db.Exec(query,
		resource.Name, resource.Description, string(scopesJSON), resource.URI,
	)
	return err
}

func (r *ResourceRepository) Delete(uri string) error {
	_, err := r.db.Exec("DELETE FROM resources WHERE uri = ?", uri)
	return err
}
