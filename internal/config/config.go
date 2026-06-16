package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Security SecurityConfig `yaml:"security"`
	Queue    QueueConfig    `yaml:"queue"`
	OIDC     OIDCConfig     `yaml:"oidc"`
}

type ServerConfig struct {
	Host string    `yaml:"host"`
	Port int       `yaml:"port"`
	TLS  TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ClientCA   string `yaml:"client_ca"`
	ClientAuth string `yaml:"client_auth"`
	CRLFile    string `yaml:"crl_file"`
}

type DatabaseConfig struct {
	Path       string `yaml:"path"`
	Migrations bool   `yaml:"migrations"`
}

type SecurityConfig struct {
	AccessTokenLifetime       time.Duration `yaml:"access_token_lifetime"`
	RefreshTokenLifetime      time.Duration `yaml:"refresh_token_lifetime"`
	AuthorizationCodeLifetime time.Duration `yaml:"authorization_code_lifetime"`
	DeviceCodeLifetime        time.Duration `yaml:"device_code_lifetime"`
	CIBARequestLifetime       time.Duration `yaml:"ciba_request_lifetime"`
	RequestURILifetime        time.Duration `yaml:"request_uri_lifetime"`
	RequirePKCE               bool          `yaml:"require_pkce"`
	AllowPlainPKCE            bool          `yaml:"allow_plain_pkce"`
	Issuer                    string        `yaml:"issuer"`
	MFA                       MFAConfig     `yaml:"mfa"`
	MTLS                      MTLSConfig    `yaml:"mtls"`
	DPoP                      DPoPConfig    `yaml:"dpop"`
}

type MFAConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Required bool   `yaml:"required"`
	Issuer   string `yaml:"issuer"`
	Digits   int    `yaml:"digits"`
	Period   uint   `yaml:"period"`
}

type MTLSConfig struct {
	Enabled          bool `yaml:"enabled"`
	CertBinding      bool `yaml:"cert_binding"`
	BindRefreshToken bool `yaml:"bind_refresh_token"`
	RequireForToken  bool `yaml:"require_for_token"`
}

type DPoPConfig struct {
	Enabled       bool `yaml:"enabled"`
	ProofLifetime int  `yaml:"proof_lifetime"`
	NonceRequired bool `yaml:"nonce_required"`
	NonceLifetime int  `yaml:"nonce_lifetime"`
}

type QueueConfig struct {
	Type         string        `yaml:"type"`
	PollInterval time.Duration `yaml:"poll_interval"`
	MaxPending   int           `yaml:"max_pending"`
}

type OIDCConfig struct {
	Issuer               string   `yaml:"issuer"`
	SigningKey           string   `yaml:"signing_key"`
	SupportedScopes      []string `yaml:"supported_scopes"`
	SupportedClaims      []string `yaml:"supported_claims"`
	SupportedGrantTypes  []string `yaml:"supported_grant_types"`
	SupportedAuthMethods []string `yaml:"supported_auth_methods"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
			TLS: TLSConfig{
				Enabled:    false,
				ClientAuth: "none",
			},
		},
		Database: DatabaseConfig{
			Path:       "./oauth.db",
			Migrations: true,
		},
		Security: SecurityConfig{
			AccessTokenLifetime:       3600 * time.Second,
			RefreshTokenLifetime:      86400 * time.Second,
			AuthorizationCodeLifetime: 600 * time.Second,
			DeviceCodeLifetime:        1800 * time.Second,
			CIBARequestLifetime:       120 * time.Second,
			RequestURILifetime:        60 * time.Second,
			RequirePKCE:               false,
			AllowPlainPKCE:            true,
			Issuer:                    "http://localhost:8080",
			MFA: MFAConfig{
				Enabled:  false,
				Required: false,
				Issuer:   "OAuthImplServer",
				Digits:   6,
				Period:   30,
			},
			MTLS: MTLSConfig{
				Enabled:          false,
				CertBinding:      false,
				BindRefreshToken: false,
				RequireForToken:  false,
			},
			DPoP: DPoPConfig{
				Enabled:       false,
				ProofLifetime: 300,
				NonceRequired: false,
				NonceLifetime: 300,
			},
		},
		Queue: QueueConfig{
			Type:         "memory",
			PollInterval: 5 * time.Second,
			MaxPending:   100,
		},
		OIDC: OIDCConfig{
			Issuer: "http://localhost:8080",
			SupportedScopes: []string{
				"openid", "profile", "email", "address", "phone", "offline_access",
			},
			SupportedClaims: []string{
				"sub", "name", "given_name", "family_name", "middle_name",
				"nickname", "preferred_username", "profile", "picture",
				"website", "email", "email_verified", "gender", "birthdate",
				"zoneinfo", "locale", "phone_number", "phone_number_verified",
				"address", "updated_at",
			},
			SupportedGrantTypes: []string{
				"authorization_code",
				"client_credentials",
				"refresh_token",
				"urn:ietf:params:oauth:grant-type:device_code",
				"urn:openid:params:grant-type:ciba",
				"urn:ietf:params:oauth:grant-type:token-exchange",
			},
			SupportedAuthMethods: []string{
				"client_secret_basic",
				"client_secret_post",
				"client_secret_jwt",
				"private_key_jwt",
				"none",
				"tls_client_auth",
				"self_signed_tls_client_auth",
			},
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
