package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func New(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}

	if _, err := conn.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	db := &DB{conn: conn}
	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) Migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			secret TEXT,
			name TEXT NOT NULL,
			redirect_uris TEXT,
			grant_types TEXT,
			scopes TEXT,
			token_endpoint_auth_method TEXT DEFAULT 'client_secret_basic',
			dpop_bound_access_tokens INTEGER DEFAULT 0,
			require_pushed_authorization_requests INTEGER DEFAULT 0,
			backchannel_token_delivery_mode TEXT,
			backchannel_client_notification_endpoint TEXT,
			backchannel_authentication_request_signing_alg TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT,
			phone_number TEXT,
			mfa_enabled INTEGER DEFAULT 0,
			mfa_secret TEXT,
			mfa_pending_secret TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS authorization_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			scopes TEXT,
			code_challenge TEXT,
			code_challenge_method TEXT,
			expires_at DATETIME NOT NULL,
			used INTEGER DEFAULT 0,
			FOREIGN KEY (client_id) REFERENCES clients(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS access_tokens (
			token TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id TEXT,
			scopes TEXT,
			token_type TEXT DEFAULT 'Bearer',
			dpop_jkt TEXT,
			expires_at DATETIME NOT NULL,
			revoked INTEGER DEFAULT 0,
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			token TEXT PRIMARY KEY,
			access_token TEXT,
			client_id TEXT NOT NULL,
			user_id TEXT,
			scopes TEXT,
			expires_at DATETIME,
			revoked INTEGER DEFAULT 0,
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE TABLE IF NOT EXISTS device_codes (
			device_code TEXT PRIMARY KEY,
			user_code TEXT NOT NULL,
			client_id TEXT NOT NULL,
			scopes TEXT,
			status TEXT DEFAULT 'pending',
			expires_at DATETIME NOT NULL,
			interval INTEGER DEFAULT 5,
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE TABLE IF NOT EXISTS pushed_auth_requests (
			request_uri TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			request_params TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE TABLE IF NOT EXISTS ciba_requests (
			auth_req_id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id TEXT,
			binding_message TEXT,
			user_code TEXT,
			status TEXT DEFAULT 'pending',
			delivery_mode TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			interval INTEGER DEFAULT 5,
			client_notification_token TEXT,
			FOREIGN KEY (client_id) REFERENCES clients(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS oidc_nonces (
			nonce TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS dpop_proofs (
			jti TEXT PRIMARY KEY,
			htm TEXT NOT NULL,
			htu TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_client ON authorization_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_status ON device_codes(status)`,
		`CREATE INDEX IF NOT EXISTS idx_ciba_requests_status ON ciba_requests(status)`,
	}

	for _, migration := range migrations {
		if _, err := db.conn.Exec(migration); err != nil {
			return fmt.Errorf("failed to execute migration: %w", err)
		}
	}

	return nil
}

func (db *DB) CreateClient(client *models.Client) error {
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	scopes, _ := json.Marshal(client.Scopes)

	query := `INSERT INTO clients (id, secret, name, redirect_uris, grant_types, scopes,
		token_endpoint_auth_method, dpop_bound_access_tokens,
		require_pushed_authorization_requests, backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
		created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		client.ID, client.Secret, client.Name,
		string(redirectURIs), string(grantTypes), string(scopes),
		client.TokenEndpointAuthMethod, client.DPoPBoundAccessTokens,
		client.RequirePushedAuthorizationRequests, client.BackchannelTokenDeliveryMode,
		client.BackchannelClientNotificationEndpoint, client.BackchannelAuthenticationRequestSigningAlg,
		client.CreatedAt, client.UpdatedAt,
	)
	return err
}

func (db *DB) GetClient(id string) (*models.Client, error) {
	query := `SELECT id, secret, name, redirect_uris, grant_types, scopes,
		token_endpoint_auth_method, dpop_bound_access_tokens,
		require_pushed_authorization_requests, backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
		created_at, updated_at
		FROM clients WHERE id = ?`

	client := &models.Client{}
	var redirectURIs, grantTypes, scopes string

	err := db.conn.QueryRow(query, id).Scan(
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

func (db *DB) ListClients() ([]*models.Client, error) {
	query := `SELECT id, secret, name, redirect_uris, grant_types, scopes,
		token_endpoint_auth_method, dpop_bound_access_tokens,
		require_pushed_authorization_requests, backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
		created_at, updated_at
		FROM clients ORDER BY created_at DESC`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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

func (db *DB) UpdateClient(client *models.Client) error {
	redirectURIs, _ := json.Marshal(client.RedirectURIs)
	grantTypes, _ := json.Marshal(client.GrantTypes)
	scopes, _ := json.Marshal(client.Scopes)

	query := `UPDATE clients SET name=?, redirect_uris=?, grant_types=?, scopes=?,
		token_endpoint_auth_method=?, dpop_bound_access_tokens=?,
		require_pushed_authorization_requests=?, backchannel_token_delivery_mode=?,
		backchannel_client_notification_endpoint=?, backchannel_authentication_request_signing_alg=?,
		updated_at=?
		WHERE id=?`

	_, err := db.conn.Exec(query,
		client.Name, string(redirectURIs), string(grantTypes), string(scopes),
		client.TokenEndpointAuthMethod, client.DPoPBoundAccessTokens,
		client.RequirePushedAuthorizationRequests, client.BackchannelTokenDeliveryMode,
		client.BackchannelClientNotificationEndpoint, client.BackchannelAuthenticationRequestSigningAlg,
		time.Now(), client.ID,
	)
	return err
}

func (db *DB) DeleteClient(id string) error {
	_, err := db.conn.Exec("DELETE FROM clients WHERE id = ?", id)
	return err
}

func (db *DB) CreateUser(user *models.User) error {
	query := `INSERT INTO users (id, username, password_hash, email, phone_number, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		user.ID, user.Username, user.PasswordHash,
		user.Email, user.PhoneNumber, user.CreatedAt,
	)
	return err
}

func (db *DB) GetUser(id string) (*models.User, error) {
	query := `SELECT id, username, password_hash, email, phone_number, created_at
		FROM users WHERE id = ?`

	user := &models.User{}
	err := db.conn.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.Email, &user.PhoneNumber, &user.CreatedAt,
	)
	return user, err
}

func (db *DB) GetUserByUsername(username string) (*models.User, error) {
	query := `SELECT id, username, password_hash, email, phone_number, created_at
		FROM users WHERE username = ?`

	user := &models.User{}
	err := db.conn.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.Email, &user.PhoneNumber, &user.CreatedAt,
	)
	return user, err
}

func (db *DB) ListUsers() ([]*models.User, error) {
	query := `SELECT id, username, password_hash, email, phone_number, created_at
		FROM users ORDER BY created_at DESC`

	rows, err := db.conn.Query(query)
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

func (db *DB) SaveAuthorizationCode(code *models.AuthorizationCode) error {
	scopes, _ := json.Marshal(code.Scopes)
	query := `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes,
		code_challenge, code_challenge_method, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		code.Code, code.ClientID, code.UserID, code.RedirectURI,
		string(scopes), code.CodeChallenge, code.CodeChallengeMethod,
		code.ExpiresAt, code.Used,
	)
	return err
}

func (db *DB) GetAuthorizationCode(code string) (*models.AuthorizationCode, error) {
	query := `SELECT code, client_id, user_id, redirect_uri, scopes,
		code_challenge, code_challenge_method, expires_at, used
		FROM authorization_codes WHERE code = ?`

	ac := &models.AuthorizationCode{}
	var scopes string

	err := db.conn.QueryRow(query, code).Scan(
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

func (db *DB) UseAuthorizationCode(code string) error {
	_, err := db.conn.Exec("UPDATE authorization_codes SET used = 1 WHERE code = ?", code)
	return err
}

func (db *DB) SaveAccessToken(token *models.AccessToken) error {
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO access_tokens (token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		token.Token, token.ClientID, token.UserID,
		string(scopes), token.TokenType, token.DPoPJKT,
		token.ExpiresAt, token.Revoked,
	)
	return err
}

func (db *DB) GetAccessToken(token string) (*models.AccessToken, error) {
	query := `SELECT token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked
		FROM access_tokens WHERE token = ?`

	at := &models.AccessToken{}
	var scopes string

	err := db.conn.QueryRow(query, token).Scan(
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

func (db *DB) RevokeAccessToken(token string) error {
	_, err := db.conn.Exec("UPDATE access_tokens SET revoked = 1 WHERE token = ?", token)
	return err
}

func (db *DB) SaveRefreshToken(token *models.RefreshToken) error {
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO refresh_tokens (token, access_token, client_id, user_id, scopes, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		token.Token, token.AccessToken, token.ClientID,
		token.UserID, string(scopes), token.ExpiresAt, token.Revoked,
	)
	return err
}

func (db *DB) GetRefreshToken(token string) (*models.RefreshToken, error) {
	query := `SELECT token, access_token, client_id, user_id, scopes, expires_at, revoked
		FROM refresh_tokens WHERE token = ?`

	rt := &models.RefreshToken{}
	var scopes string

	err := db.conn.QueryRow(query, token).Scan(
		&rt.Token, &rt.AccessToken, &rt.ClientID,
		&rt.UserID, &scopes, &rt.ExpiresAt, &rt.Revoked,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &rt.Scopes); err != nil {
		return nil, err
	}
	return rt, nil
}

func (db *DB) RevokeRefreshToken(token string) error {
	_, err := db.conn.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", token)
	return err
}

func (db *DB) SaveDeviceCode(dc *models.DeviceCode) error {
	scopes, _ := json.Marshal(dc.Scopes)
	query := `INSERT INTO device_codes (device_code, user_code, client_id, scopes, status, expires_at, interval)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		dc.DeviceCode, dc.UserCode, dc.ClientID,
		string(scopes), dc.Status, dc.ExpiresAt, dc.Interval,
	)
	return err
}

func (db *DB) GetDeviceCode(deviceCode string) (*models.DeviceCode, error) {
	query := `SELECT device_code, user_code, client_id, scopes, status, expires_at, interval
		FROM device_codes WHERE device_code = ?`

	dc := &models.DeviceCode{}
	var scopes string

	err := db.conn.QueryRow(query, deviceCode).Scan(
		&dc.DeviceCode, &dc.UserCode, &dc.ClientID,
		&scopes, &dc.Status, &dc.ExpiresAt, &dc.Interval,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &dc.Scopes); err != nil {
		return nil, err
	}
	return dc, nil
}

func (db *DB) GetDeviceCodeByUserCode(userCode string) (*models.DeviceCode, error) {
	query := `SELECT device_code, user_code, client_id, scopes, status, expires_at, interval
		FROM device_codes WHERE user_code = ?`

	dc := &models.DeviceCode{}
	var scopes string

	err := db.conn.QueryRow(query, userCode).Scan(
		&dc.DeviceCode, &dc.UserCode, &dc.ClientID,
		&scopes, &dc.Status, &dc.ExpiresAt, &dc.Interval,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(scopes), &dc.Scopes); err != nil {
		return nil, err
	}
	return dc, nil
}

func (db *DB) UpdateDeviceCodeStatus(deviceCode, status string) error {
	_, err := db.conn.Exec("UPDATE device_codes SET status = ? WHERE device_code = ?", status, deviceCode)
	return err
}

func (db *DB) SavePushedAuthRequest(par *models.PushedAuthRequest) error {
	query := `INSERT INTO pushed_auth_requests (request_uri, client_id, request_params, expires_at)
		VALUES (?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		par.RequestURI, par.ClientID, par.RequestParams, par.ExpiresAt,
	)
	return err
}

func (db *DB) GetPushedAuthRequest(requestURI string) (*models.PushedAuthRequest, error) {
	query := `SELECT request_uri, client_id, request_params, expires_at
		FROM pushed_auth_requests WHERE request_uri = ?`

	par := &models.PushedAuthRequest{}
	err := db.conn.QueryRow(query, requestURI).Scan(
		&par.RequestURI, &par.ClientID, &par.RequestParams, &par.ExpiresAt,
	)
	return par, err
}

func (db *DB) SaveCIBARequest(req *models.CIBARequest) error {
	query := `INSERT INTO ciba_requests (auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		req.AuthReqID, req.ClientID, req.UserID, req.BindingMessage,
		req.UserCode, req.Status, req.DeliveryMode, req.ExpiresAt,
		req.Interval, req.ClientNotificationToken,
	)
	return err
}

func (db *DB) GetCIBARequest(authReqID string) (*models.CIBARequest, error) {
	query := `SELECT auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token
		FROM ciba_requests WHERE auth_req_id = ?`

	req := &models.CIBARequest{}
	err := db.conn.QueryRow(query, authReqID).Scan(
		&req.AuthReqID, &req.ClientID, &req.UserID, &req.BindingMessage,
		&req.UserCode, &req.Status, &req.DeliveryMode, &req.ExpiresAt,
		&req.Interval, &req.ClientNotificationToken,
	)
	return req, err
}

func (db *DB) UpdateCIBARequestStatus(authReqID, status string) error {
	_, err := db.conn.Exec("UPDATE ciba_requests SET status = ? WHERE auth_req_id = ?", status, authReqID)
	return err
}

func (db *DB) GetPendingCIBARequests() ([]*models.CIBARequest, error) {
	query := `SELECT auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token
		FROM ciba_requests WHERE status = 'pending' AND expires_at > ?
		ORDER BY expires_at DESC`

	rows, err := db.conn.Query(query, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	requests := make([]*models.CIBARequest, 0)
	for rows.Next() {
		req := &models.CIBARequest{}
		err := rows.Scan(
			&req.AuthReqID, &req.ClientID, &req.UserID, &req.BindingMessage,
			&req.UserCode, &req.Status, &req.DeliveryMode, &req.ExpiresAt,
			&req.Interval, &req.ClientNotificationToken,
		)
		if err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}
	return requests, nil
}

func (db *DB) SaveDPoPProof(proof *models.DPoPProof) error {
	query := `INSERT INTO dpop_proofs (jti, htm, htu, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`

	_, err := db.conn.Exec(query,
		proof.JTI, proof.HTM, proof.HTU, proof.CreatedAt, proof.ExpiresAt,
	)
	return err
}

func (db *DB) GetDPoPProof(jti string) (*models.DPoPProof, error) {
	query := `SELECT jti, htm, htu, created_at, expires_at
		FROM dpop_proofs WHERE jti = ?`

	proof := &models.DPoPProof{}
	err := db.conn.QueryRow(query, jti).Scan(
		&proof.JTI, &proof.HTM, &proof.HTU, &proof.CreatedAt, &proof.ExpiresAt,
	)
	return proof, err
}

func (db *DB) SaveOIDCNonce(nonce *models.OIDCNonce) error {
	query := `INSERT INTO oidc_nonces (nonce, client_id, expires_at) VALUES (?, ?, ?)`

	_, err := db.conn.Exec(query, nonce.Nonce, nonce.ClientID, nonce.ExpiresAt)
	return err
}

func (db *DB) GetOIDCNonce(nonce string) (*models.OIDCNonce, error) {
	query := `SELECT nonce, client_id, expires_at FROM oidc_nonces WHERE nonce = ?`

	n := &models.OIDCNonce{}
	err := db.conn.QueryRow(query, nonce).Scan(&n.Nonce, &n.ClientID, &n.ExpiresAt)
	return n, err
}

func (db *DB) ListAccessTokens(clientID, userID string) ([]*models.AccessToken, error) {
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

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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

func (db *DB) CleanupExpired() error {
	now := time.Now()
	tables := []struct {
		table   string
		timeCol string
	}{
		{"authorization_codes", "expires_at"},
		{"access_tokens", "expires_at"},
		{"refresh_tokens", "expires_at"},
		{"device_codes", "expires_at"},
		{"pushed_auth_requests", "expires_at"},
		{"ciba_requests", "expires_at"},
		{"oidc_nonces", "expires_at"},
		{"dpop_proofs", "expires_at"},
	}

	for _, t := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE %s < ?", t.table, t.timeCol)
		if _, err := db.conn.Exec(query, now); err != nil {
			return fmt.Errorf("failed to cleanup %s: %w", t.table, err)
		}
	}
	return nil
}
