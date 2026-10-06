package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// SQL is the query handle repositories use. Postgres placeholders are rewritten.
type SQL interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Dialect() string
}

func (db *DB) Dialect() string {
	if db == nil || db.driver == "" {
		return "sqlite"
	}
	return db.driver
}

type DB struct {
	conn   *sql.DB
	driver string
}

// New opens a SQLite file. Tests and the default server use this.
func New(dbPath string) (*DB, error) {
	return openSQLite(dbPath)
}

// Open selects sqlite or postgres from config.
func Open(cfg *config.Config) (*DB, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	switch cfg.Database.Driver {
	case "", "sqlite":
		if cfg.Database.Path == "" {
			return nil, fmt.Errorf("database.path is required for sqlite")
		}
		return openSQLite(cfg.Database.Path)
	case "postgres":
		if cfg.Database.DSN == "" {
			return nil, fmt.Errorf("database.dsn is required for postgres")
		}
		return openPostgres(cfg.Database.DSN)
	default:
		return nil, fmt.Errorf("database.driver must be sqlite or postgres")
	}
}

func openSQLite(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	db := &DB{conn: conn, driver: "sqlite"}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	return db, nil
}

func openPostgres(dsn string) (*DB, error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("postgres: %w", err)
	}
	return &DB{conn: conn, driver: "postgres"}, nil
}

func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	return db.conn.Exec(db.prepare(query), args...)
}

func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return db.conn.Query(db.prepare(query), args...)
}

func (db *DB) QueryRow(query string, args ...any) *sql.Row {
	return db.conn.QueryRow(db.prepare(query), args...)
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
			resource TEXT,
			nonce TEXT,
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
			cert_thumbprint TEXT,
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

		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			username TEXT,
			auth_time DATETIME NOT NULL,
			mfa_verified INTEGER NOT NULL DEFAULT 0,
			user_agent TEXT,
			ip TEXT,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE TABLE IF NOT EXISTS session_clients (
			sid TEXT NOT NULL,
			client_id TEXT NOT NULL,
			PRIMARY KEY (sid, client_id)
		)`,
		`CREATE TABLE IF NOT EXISTS email_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			purpose TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME,
			created_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_email_tokens_hash ON email_tokens(token_hash)`,
		`CREATE TABLE IF NOT EXISTS login_events (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			success INTEGER NOT NULL,
			mfa INTEGER NOT NULL DEFAULT 0,
			ip TEXT,
			user_agent TEXT,
			created_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_login_events_user ON login_events(user_id, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_login_events_ip ON login_events(ip, created_at)`,
		`CREATE TABLE IF NOT EXISTS schema_flags (
			name TEXT PRIMARY KEY
		)`,
		`CREATE TABLE IF NOT EXISTS social_logins (
			state TEXT PRIMARY KEY,
			provider TEXT NOT NULL,
			verifier TEXT NOT NULL,
			nonce TEXT NOT NULL,
			params_json TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			used INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS social_identities (
			provider TEXT NOT NULL,
			subject TEXT NOT NULL,
			user_id TEXT NOT NULL,
			email TEXT,
			created_at TEXT NOT NULL,
			PRIMARY KEY (provider, subject)
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			actor_type TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			action TEXT NOT NULL,
			target_type TEXT,
			target_id TEXT,
			ip TEXT,
			user_agent TEXT,
			metadata TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS signing_keys (
			kid TEXT PRIMARY KEY,
			alg TEXT NOT NULL,
			status TEXT NOT NULL,
			private_pem TEXT NOT NULL,
			created_at TEXT NOT NULL,
			retire_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS webhooks (
			id TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			secret TEXT NOT NULL,
			events TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			description TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,

		// Consent persistence
		`CREATE TABLE IF NOT EXISTS consents (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			scopes TEXT NOT NULL,
			granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_consents_user_client ON consents(user_id, client_id)`,

		// Custom scope definitions
		`CREATE TABLE IF NOT EXISTS scopes (
			name TEXT PRIMARY KEY,
			description TEXT,
			resource_server TEXT,
			is_default INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Resource servers (RFC 8707)
		`CREATE TABLE IF NOT EXISTS resources (
			uri TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			scopes TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("failed to execute migration: %w", err)
		}
	}

	// Safe ALTER TABLE migrations (ignore "duplicate column" errors)
	alters := []string{
		`ALTER TABLE access_tokens ADD COLUMN resource TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN resource TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN nonce TEXT`,
		`ALTER TABLE refresh_tokens ADD COLUMN resource TEXT`,
		`ALTER TABLE users ADD COLUMN last_login_at DATETIME`,
		`ALTER TABLE clients ADD COLUMN jwks TEXT`,
		`ALTER TABLE clients ADD COLUMN jwks_uri TEXT`,
		`ALTER TABLE clients ADD COLUMN request_object_signing_alg TEXT`,
		`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN given_name TEXT`,
		`ALTER TABLE users ADD COLUMN family_name TEXT`,
		`ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT`,
		`ALTER TABLE clients ADD COLUMN backchannel_logout_session_required INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE clients ADD COLUMN post_logout_redirect_uris TEXT`,
		`ALTER TABLE device_codes ADD COLUMN user_id TEXT`,
		`ALTER TABLE device_codes ADD COLUMN session_id TEXT`,
		`ALTER TABLE device_codes ADD COLUMN auth_time DATETIME`,
		`ALTER TABLE refresh_tokens ADD COLUMN id TEXT`,
		`ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN family_id TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN session_id TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN auth_time DATETIME`,
		`ALTER TABLE users ADD COLUMN attributes TEXT NOT NULL DEFAULT '{}'`,
		`ALTER TABLE clients ADD COLUMN registration_source TEXT NOT NULL DEFAULT 'management'`,
		`ALTER TABLE clients ADD COLUMN dcr_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE clients ADD COLUMN cimd_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ciba_requests ADD COLUMN scopes TEXT`,
	}
	for _, alter := range alters {
		if _, err := db.Exec(alter); err != nil && db.driver == "postgres" && !isDuplicateColumn(err) {
			return fmt.Errorf("failed to execute migration: %w", err)
		}
	}

	if _, err := db.Exec(`INSERT INTO schema_flags (name) VALUES ('email_verified_backfill')`); err == nil {
		_, _ = db.Exec(`UPDATE users SET email_verified = 1 WHERE email IS NOT NULL AND email != ''`)
	}
	if err := db.backfillRefreshIDs(); err != nil {
		return err
	}

	return nil
}

func isDuplicateColumn(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42701"
}

func (db *DB) backfillRefreshIDs() error {
	rows, err := db.Query(`SELECT token FROM refresh_tokens WHERE id IS NULL OR id = '' OR family_id IS NULL OR family_id = ''`)
	if err != nil {
		return fmt.Errorf("refresh token ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return err
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, token := range tokens {
		if _, err := db.Exec(`UPDATE refresh_tokens SET
			id = CASE WHEN id IS NULL OR id = '' THEN ? ELSE id END,
			family_id = CASE WHEN family_id IS NULL OR family_id = '' THEN ? ELSE family_id END
			WHERE token = ?`, newID(), newID(), token); err != nil {
			return fmt.Errorf("refresh token ids: %w", err)
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

	_, err := db.Exec(query,
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

	err := db.QueryRow(query, id).Scan(
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

	rows, err := db.Query(query)
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

	_, err := db.Exec(query,
		client.Name, string(redirectURIs), string(grantTypes), string(scopes),
		client.TokenEndpointAuthMethod, client.DPoPBoundAccessTokens,
		client.RequirePushedAuthorizationRequests, client.BackchannelTokenDeliveryMode,
		client.BackchannelClientNotificationEndpoint, client.BackchannelAuthenticationRequestSigningAlg,
		time.Now(), client.ID,
	)
	return err
}

func (db *DB) DeleteClient(id string) error {
	_, err := db.Exec("DELETE FROM clients WHERE id = ?", id)
	return err
}

func parseAttributes(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" || raw == "{}" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	if out == nil {
		return map[string]string{}
	}
	return out
}

func (db *DB) CreateUser(user *models.User) error {
	query := `INSERT INTO users (id, username, password_hash, email, phone_number, created_at,
		email_verified, disabled, given_name, family_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query,
		user.ID, user.Username, user.PasswordHash,
		user.Email, user.PhoneNumber, user.CreatedAt,
		user.EmailVerified, user.Disabled, user.GivenName, user.FamilyName,
	)
	return err
}

func (db *DB) GetUser(id string) (*models.User, error) {
	query := `SELECT id, username, password_hash, COALESCE(email, ''), COALESCE(phone_number, ''), created_at,
		last_login_at, COALESCE(email_verified, 0), COALESCE(disabled, 0), COALESCE(given_name, ''), COALESCE(family_name, ''), COALESCE(attributes, '{}')
		FROM users WHERE id = ?`

	user := &models.User{}
	var lastLogin sql.NullTime
	var emailVerified, disabled int
	var attrs string
	err := db.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.Email, &user.PhoneNumber, &user.CreatedAt,
		&lastLogin, &emailVerified, &disabled, &user.GivenName, &user.FamilyName, &attrs,
	)
	if err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		user.LastLoginAt = &t
	}
	user.EmailVerified = emailVerified != 0
	user.Disabled = disabled != 0
	user.Attributes = parseAttributes(attrs)
	return user, nil
}

func (db *DB) GetUserByUsername(username string) (*models.User, error) {
	query := `SELECT id, username, password_hash, COALESCE(email, ''), COALESCE(phone_number, ''), created_at,
		last_login_at, COALESCE(email_verified, 0), COALESCE(disabled, 0), COALESCE(given_name, ''), COALESCE(family_name, ''), COALESCE(attributes, '{}')
		FROM users WHERE username = ?`

	user := &models.User{}
	var lastLogin sql.NullTime
	var emailVerified, disabled int
	var attrs string
	err := db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.Email, &user.PhoneNumber, &user.CreatedAt,
		&lastLogin, &emailVerified, &disabled, &user.GivenName, &user.FamilyName, &attrs,
	)
	if err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		user.LastLoginAt = &t
	}
	user.EmailVerified = emailVerified != 0
	user.Disabled = disabled != 0
	user.Attributes = parseAttributes(attrs)
	return user, nil
}

func (db *DB) ListUsers() ([]*models.User, error) {
	query := `SELECT id, username, password_hash, COALESCE(email, ''), COALESCE(phone_number, ''), created_at,
		last_login_at, COALESCE(email_verified, 0), COALESCE(disabled, 0), COALESCE(given_name, ''), COALESCE(family_name, ''), COALESCE(attributes, '{}')
		FROM users ORDER BY created_at DESC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	users := make([]*models.User, 0)
	for rows.Next() {
		user := &models.User{}
		var lastLogin sql.NullTime
		var emailVerified, disabled int
		var attrs string
		err := rows.Scan(
			&user.ID, &user.Username, &user.PasswordHash,
			&user.Email, &user.PhoneNumber, &user.CreatedAt,
			&lastLogin, &emailVerified, &disabled, &user.GivenName, &user.FamilyName, &attrs,
		)
		if err != nil {
			return nil, err
		}
		if lastLogin.Valid {
			t := lastLogin.Time
			user.LastLoginAt = &t
		}
		user.EmailVerified = emailVerified != 0
		user.Disabled = disabled != 0
		user.Attributes = parseAttributes(attrs)
		users = append(users, user)
	}
	return users, nil
}

func (db *DB) SaveAuthorizationCode(code *models.AuthorizationCode) error {
	scopes, _ := json.Marshal(code.Scopes)
	query := `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes,
		code_challenge, code_challenge_method, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query,
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

	err := db.QueryRow(query, code).Scan(
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
	_, err := db.Exec("UPDATE authorization_codes SET used = 1 WHERE code = ?", code)
	return err
}

func (db *DB) SaveAccessToken(token *models.AccessToken) error {
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO access_tokens (token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query,
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

	err := db.QueryRow(query, token).Scan(
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
	_, err := db.Exec("UPDATE access_tokens SET revoked = 1 WHERE token = ?", token)
	return err
}

func (db *DB) SaveRefreshToken(token *models.RefreshToken) error {
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO refresh_tokens (token, access_token, client_id, user_id, scopes, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query,
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

	err := db.QueryRow(query, token).Scan(
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
	_, err := db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", token)
	return err
}

func (db *DB) SaveDeviceCode(dc *models.DeviceCode) error {
	scopes, _ := json.Marshal(dc.Scopes)
	query := `INSERT INTO device_codes (device_code, user_code, client_id, scopes, status, expires_at, interval)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query,
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

	err := db.QueryRow(query, deviceCode).Scan(
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

	err := db.QueryRow(query, userCode).Scan(
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
	_, err := db.Exec("UPDATE device_codes SET status = ? WHERE device_code = ?", status, deviceCode)
	return err
}

func (db *DB) SavePushedAuthRequest(par *models.PushedAuthRequest) error {
	query := `INSERT INTO pushed_auth_requests (request_uri, client_id, request_params, expires_at)
		VALUES (?, ?, ?, ?)`

	_, err := db.Exec(query,
		par.RequestURI, par.ClientID, par.RequestParams, par.ExpiresAt,
	)
	return err
}

func (db *DB) GetPushedAuthRequest(requestURI string) (*models.PushedAuthRequest, error) {
	query := `SELECT request_uri, client_id, request_params, expires_at
		FROM pushed_auth_requests WHERE request_uri = ?`

	par := &models.PushedAuthRequest{}
	err := db.QueryRow(query, requestURI).Scan(
		&par.RequestURI, &par.ClientID, &par.RequestParams, &par.ExpiresAt,
	)
	return par, err
}

func (db *DB) SaveCIBARequest(req *models.CIBARequest) error {
	query := `INSERT INTO ciba_requests (auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query,
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
	err := db.QueryRow(query, authReqID).Scan(
		&req.AuthReqID, &req.ClientID, &req.UserID, &req.BindingMessage,
		&req.UserCode, &req.Status, &req.DeliveryMode, &req.ExpiresAt,
		&req.Interval, &req.ClientNotificationToken,
	)
	return req, err
}

func (db *DB) UpdateCIBARequestStatus(authReqID, status string) error {
	_, err := db.Exec("UPDATE ciba_requests SET status = ? WHERE auth_req_id = ?", status, authReqID)
	return err
}

func (db *DB) GetPendingCIBARequests() ([]*models.CIBARequest, error) {
	query := `SELECT auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token
		FROM ciba_requests WHERE status = 'pending' AND expires_at > ?
		ORDER BY expires_at DESC`

	rows, err := db.Query(query, time.Now())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

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

	_, err := db.Exec(query,
		proof.JTI, proof.HTM, proof.HTU, proof.CreatedAt, proof.ExpiresAt,
	)
	return err
}

func (db *DB) GetDPoPProof(jti string) (*models.DPoPProof, error) {
	query := `SELECT jti, htm, htu, created_at, expires_at
		FROM dpop_proofs WHERE jti = ?`

	proof := &models.DPoPProof{}
	err := db.QueryRow(query, jti).Scan(
		&proof.JTI, &proof.HTM, &proof.HTU, &proof.CreatedAt, &proof.ExpiresAt,
	)
	return proof, err
}

func (db *DB) SaveOIDCNonce(nonce *models.OIDCNonce) error {
	query := `INSERT INTO oidc_nonces (nonce, client_id, expires_at) VALUES (?, ?, ?)`

	_, err := db.Exec(query, nonce.Nonce, nonce.ClientID, nonce.ExpiresAt)
	return err
}

func (db *DB) GetOIDCNonce(nonce string) (*models.OIDCNonce, error) {
	query := `SELECT nonce, client_id, expires_at FROM oidc_nonces WHERE nonce = ?`

	n := &models.OIDCNonce{}
	err := db.QueryRow(query, nonce).Scan(&n.Nonce, &n.ClientID, &n.ExpiresAt)
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

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

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
		if _, err := db.Exec(query, now); err != nil {
			return fmt.Errorf("failed to cleanup %s: %w", t.table, err)
		}
	}
	return nil
}
