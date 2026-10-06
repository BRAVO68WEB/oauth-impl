package repository

import (
	"database/sql"
	"github.com/bravo68web/oauth-impl/internal/database"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type ScopeRepository struct {
	db database.SQL
}

func NewScopeRepository(db database.SQL) *ScopeRepository {
	return &ScopeRepository{db: db}
}

func (r *ScopeRepository) Create(scope *models.Scope) error {
	query := `INSERT INTO scopes (name, description, resource_server, is_default, created_at)
		VALUES (?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		scope.Name, scope.Description, scope.ResourceServer,
		scope.IsDefault, time.Now(),
	)
	return err
}

func (r *ScopeRepository) Get(name string) (*models.Scope, error) {
	query := `SELECT name, description, resource_server, is_default, created_at
		FROM scopes WHERE name = ?`

	scope := &models.Scope{}
	var resourceServer sql.NullString

	err := r.db.QueryRow(query, name).Scan(
		&scope.Name, &scope.Description, &resourceServer,
		&scope.IsDefault, &scope.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if resourceServer.Valid {
		scope.ResourceServer = resourceServer.String
	}

	return scope, nil
}

func (r *ScopeRepository) List() ([]*models.Scope, error) {
	query := `SELECT name, description, resource_server, is_default, created_at
		FROM scopes ORDER BY name`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	scopes := make([]*models.Scope, 0)
	for rows.Next() {
		scope := &models.Scope{}
		var resourceServer sql.NullString

		err := rows.Scan(
			&scope.Name, &scope.Description, &resourceServer,
			&scope.IsDefault, &scope.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if resourceServer.Valid {
			scope.ResourceServer = resourceServer.String
		}

		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func (r *ScopeRepository) ListByResource(resourceURI string) ([]*models.Scope, error) {
	query := `SELECT name, description, resource_server, is_default, created_at
		FROM scopes WHERE resource_server = ? ORDER BY name`

	rows, err := r.db.Query(query, resourceURI)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	scopes := make([]*models.Scope, 0)
	for rows.Next() {
		scope := &models.Scope{}
		var resourceServer sql.NullString

		err := rows.Scan(
			&scope.Name, &scope.Description, &resourceServer,
			&scope.IsDefault, &scope.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if resourceServer.Valid {
			scope.ResourceServer = resourceServer.String
		}

		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func (r *ScopeRepository) Delete(name string) error {
	_, err := r.db.Exec("DELETE FROM scopes WHERE name = ?", name)
	return err
}
