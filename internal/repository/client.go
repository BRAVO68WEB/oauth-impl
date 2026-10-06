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

	postLogout, _ := json.Marshal(client.PostLogoutRedirectURIs)
	source := client.RegistrationSource
	if source == "" {
		source = "management"
	}
	client.RegistrationSource = source
	query := `INSERT INTO clients (id, secret, name, redirect_uris, grant_types, scopes,
		token_endpoint_auth_method, dpop_bound_access_tokens,
		require_pushed_authorization_requests, backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
		backchannel_logout_uri, backchannel_logout_session_required, post_logout_redirect_uris,
		jwks, jwks_uri, request_object_signing_alg,
		registration_source, dcr_enabled, cimd_enabled,
		created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		client.ID, client.Secret, client.Name,
		string(redirectURIs), string(grantTypes), string(scopes),
		client.TokenEndpointAuthMethod, client.DPoPBoundAccessTokens,
		client.RequirePushedAuthorizationRequests, client.BackchannelTokenDeliveryMode,
		client.BackchannelClientNotificationEndpoint, client.BackchannelAuthenticationRequestSigningAlg,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired, string(postLogout),
		client.JWKS, client.JWKSUri, client.RequestObjectSigningAlg,
		source, boolInt(client.DCREnabled), boolInt(client.CIMDEnabled),
		client.CreatedAt, client.UpdatedAt,
	)
	return err
}

func (r *ClientRepository) GetByID(id string) (*models.Client, error) {
	row := r.db.QueryRow(clientSelect+` WHERE id = ?`, id)
	return scanClient(row.Scan)
}

func (r *ClientRepository) List() ([]*models.Client, error) {
	rows, err := r.db.Query(clientSelect + ` ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	clients := make([]*models.Client, 0)
	for rows.Next() {
		client, err := scanClient(rows.Scan)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (r *ClientRepository) Update(client *models.Client) error {
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	scopes, _ := json.Marshal(client.Scopes)

	postLogout, _ := json.Marshal(client.PostLogoutRedirectURIs)
	query := `UPDATE clients SET name=?, redirect_uris=?, grant_types=?, scopes=?,
		token_endpoint_auth_method=?, dpop_bound_access_tokens=?,
		require_pushed_authorization_requests=?, backchannel_token_delivery_mode=?,
		backchannel_client_notification_endpoint=?, backchannel_authentication_request_signing_alg=?,
		backchannel_logout_uri=?, backchannel_logout_session_required=?, post_logout_redirect_uris=?,
		jwks=?, jwks_uri=?, request_object_signing_alg=?,
		registration_source=?, dcr_enabled=?, cimd_enabled=?,
		updated_at=?
		WHERE id=?`

	source := client.RegistrationSource
	if source == "" {
		source = "management"
	}
	_, err := r.db.Exec(query,
		client.Name, string(redirectURIs), string(grantTypes), string(scopes),
		client.TokenEndpointAuthMethod, client.DPoPBoundAccessTokens,
		client.RequirePushedAuthorizationRequests, client.BackchannelTokenDeliveryMode,
		client.BackchannelClientNotificationEndpoint, client.BackchannelAuthenticationRequestSigningAlg,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired, string(postLogout),
		client.JWKS, client.JWKSUri, client.RequestObjectSigningAlg,
		source, boolInt(client.DCREnabled), boolInt(client.CIMDEnabled),
		time.Now(), client.ID,
	)
	return err
}

func (r *ClientRepository) Delete(id string) error {
	_, err := r.db.Exec("DELETE FROM clients WHERE id = ?", id)
	return err
}

const clientSelect = `SELECT id, secret, name, redirect_uris, grant_types, scopes,
	token_endpoint_auth_method, dpop_bound_access_tokens,
	require_pushed_authorization_requests, backchannel_token_delivery_mode,
	backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
	COALESCE(backchannel_logout_uri, ''), COALESCE(backchannel_logout_session_required, 1), COALESCE(post_logout_redirect_uris, '[]'),
	jwks, jwks_uri, request_object_signing_alg,
	COALESCE(registration_source, 'management'), COALESCE(dcr_enabled, 0), COALESCE(cimd_enabled, 0),
	created_at, updated_at
	FROM clients`

func scanClient(scan func(dest ...any) error) (*models.Client, error) {
	client := &models.Client{}
	var redirectURIs, grantTypes, scopes, postLogout, source string
	var jwks, jwksUri, reqObjAlg sql.NullString
	var sessionRequired, dcrEnabled, cimdEnabled int
	if err := scan(
		&client.ID, &client.Secret, &client.Name,
		&redirectURIs, &grantTypes, &scopes,
		&client.TokenEndpointAuthMethod, &client.DPoPBoundAccessTokens,
		&client.RequirePushedAuthorizationRequests, &client.BackchannelTokenDeliveryMode,
		&client.BackchannelClientNotificationEndpoint, &client.BackchannelAuthenticationRequestSigningAlg,
		&client.BackchannelLogoutURI, &sessionRequired, &postLogout,
		&jwks, &jwksUri, &reqObjAlg,
		&source, &dcrEnabled, &cimdEnabled,
		&client.CreatedAt, &client.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if jwks.Valid {
		client.JWKS = jwks.String
	}
	if jwksUri.Valid {
		client.JWKSUri = jwksUri.String
	}
	if reqObjAlg.Valid {
		client.RequestObjectSigningAlg = reqObjAlg.String
	}
	client.BackchannelLogoutSessionRequired = sessionRequired != 0
	client.RegistrationSource = source
	if client.RegistrationSource == "" {
		client.RegistrationSource = "management"
	}
	client.DCREnabled = dcrEnabled != 0
	client.CIMDEnabled = cimdEnabled != 0
	if err := decodeStringList(redirectURIs, &client.RedirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(grantTypes), &client.GrantTypes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopes), &client.Scopes); err != nil {
		return nil, err
	}
	if err := decodeStringList(postLogout, &client.PostLogoutRedirectURIs); err != nil {
		return nil, err
	}
	return client, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func decodeStringList(raw string, dest *[]string) error {
	if raw == "" || raw == "null" {
		*dest = []string{}
		return nil
	}
	if err := json.Unmarshal([]byte(raw), dest); err != nil {
		return err
	}
	if *dest == nil {
		*dest = []string{}
	}
	return nil
}
