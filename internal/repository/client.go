package repository

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
)

type ClientRepository struct {
	db *sql.DB
}

func NewClientRepository(db *sql.DB) *ClientRepository {
	return &ClientRepository{db: db}
}

func (r *ClientRepository) Create(client *models.Client) error {
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	scopes, _ := json.Marshal(client.Scopes)

	query := `INSERT INTO clients (id, secret, name, redirect_uris, grant_types, scopes,
		token_endpoint_auth_method, dpop_bound_access_tokens,
		require_pushed_authorization_requests, backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
		created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		client.ID, client.Secret, client.Name,
		string(redirectURIs), string(grantTypes), string(scopes),
		client.TokenEndpointAuthMethod, client.DPoPBoundAccessTokens,
		client.RequirePushedAuthorizationRequests, client.BackchannelTokenDeliveryMode,
		client.BackchannelClientNotificationEndpoint, client.BackchannelAuthenticationRequestSigningAlg,
		client.CreatedAt, client.UpdatedAt,
	)
	return err
}

func (r *ClientRepository) GetByID(id string) (*models.Client, error) {
	query := `SELECT id, secret, name, redirect_uris, grant_types, scopes,
		token_endpoint_auth_method, dpop_bound_access_tokens,
		require_pushed_authorization_requests, backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
		created_at, updated_at
		FROM clients WHERE id = ?`

	client := &models.Client{}
	var redirectURIs, grantTypes, scopes string

	err := r.db.QueryRow(query, id).Scan(
		&client.ID, &client.Secret, &client.Name,
		&redirectURIs, &grantTypes, &scopes,
		&client.TokenEndpointAuthMethod, &client.DPoPBoundAccessTokens,
		&client.RequirePushedAuthorizationRequests, &client.BackchannelTokenDeliveryMode,
		&client.BackchannelClientNotificationEndpoint, &client.BackchannelAuthenticationRequestSigningAlg,
		&client.CreatedAt, &client.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(redirectURIs), &client.RedirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(grantTypes), &client.GrantTypes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopes), &client.Scopes); err != nil {
		return nil, err
	}

	return client, nil
}

func (r *ClientRepository) List() ([]*models.Client, error) {
	query := `SELECT id, secret, name, redirect_uris, grant_types, scopes,
		token_endpoint_auth_method, dpop_bound_access_tokens,
		require_pushed_authorization_requests, backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
		created_at, updated_at
		FROM clients ORDER BY created_at DESC`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	clients := make([]*models.Client, 0)
	for rows.Next() {
		client := &models.Client{}
		var redirectURIs, grantTypes, scopes string

		err := rows.Scan(
			&client.ID, &client.Secret, &client.Name,
			&redirectURIs, &grantTypes, &scopes,
			&client.TokenEndpointAuthMethod, &client.DPoPBoundAccessTokens,
			&client.RequirePushedAuthorizationRequests, &client.BackchannelTokenDeliveryMode,
			&client.BackchannelClientNotificationEndpoint, &client.BackchannelAuthenticationRequestSigningAlg,
			&client.CreatedAt, &client.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal([]byte(redirectURIs), &client.RedirectURIs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(grantTypes), &client.GrantTypes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &client.Scopes); err != nil {
			return nil, err
		}

		clients = append(clients, client)
	}
	return clients, nil
}

func (r *ClientRepository) Update(client *models.Client) error {
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	scopes, _ := json.Marshal(client.Scopes)

	query := `UPDATE clients SET name=?, redirect_uris=?, grant_types=?, scopes=?,
		token_endpoint_auth_method=?, dpop_bound_access_tokens=?,
		require_pushed_authorization_requests=?, backchannel_token_delivery_mode=?,
		backchannel_client_notification_endpoint=?, backchannel_authentication_request_signing_alg=?,
		updated_at=?
		WHERE id=?`

	_, err := r.db.Exec(query,
		client.Name, string(redirectURIs), string(grantTypes), string(scopes),
		client.TokenEndpointAuthMethod, client.DPoPBoundAccessTokens,
		client.RequirePushedAuthorizationRequests, client.BackchannelTokenDeliveryMode,
		client.BackchannelClientNotificationEndpoint, client.BackchannelAuthenticationRequestSigningAlg,
		time.Now(), client.ID,
	)
	return err
}

func (r *ClientRepository) Delete(id string) error {
	_, err := r.db.Exec("DELETE FROM clients WHERE id = ?", id)
	return err
}
