package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/config"
)

var (
	mgmtClientID          string
	mgmtClientSecret      string
	configPath            string
	cachedManagementToken string
)

func managementToken() (string, error) {
	if cachedManagementToken != "" {
		return cachedManagementToken, nil
	}
	if err := ensureManagementCreds(); err != nil {
		return "", err
	}
	body := "grant_type=client_credentials&scope=management"
	req, err := http.NewRequest(http.MethodPost, serverURL+"/oauth/token", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(mgmtClientID, mgmtClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("management token: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("management token: %v", result["error_description"])
	}
	token, _ := result["access_token"].(string)
	if token == "" {
		return "", fmt.Errorf("management token: empty access_token")
	}
	cachedManagementToken = token
	return token, nil
}

func ensureManagementCreds() error {
	if mgmtClientID != "" && mgmtClientSecret != "" {
		return nil
	}
	path := configPath
	if path == "" {
		path = "config.yaml"
	}
	cfg, err := config.Load(path)
	if err == nil {
		if mgmtClientID == "" {
			mgmtClientID = cfg.Management.ClientID
		}
		if mgmtClientSecret == "" {
			mgmtClientSecret = cfg.Management.ClientSecret
		}
	}
	if mgmtClientID == "" || mgmtClientSecret == "" {
		return fmt.Errorf("management client credentials required (--client-id and --client-secret, or management.* in config.yaml)")
	}
	return nil
}

func withManagement(req *http.Request) (*http.Response, error) {
	token, err := managementToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}

func apiGet(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return withManagement(req)
}

func apiPut(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, rawURL, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return withManagement(req)
}

func apiPost(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return withManagement(req)
}

func apiPostForm(rawURL string, data url.Values) (*http.Response, error) {
	if data == nil {
		data = url.Values{}
	}
	return apiPost(rawURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
