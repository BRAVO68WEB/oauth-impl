package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	if mgmtClientID == "" || mgmtClientSecret == "" {
		path := configPath
		if path == "" {
			path = "config.yaml"
		}
		if cfg, err := config.Load(path); err == nil {
			if mgmtClientID == "" {
				mgmtClientID = cfg.Management.ClientID
			}
			if mgmtClientSecret == "" {
				mgmtClientSecret = cfg.Management.ClientSecret
			}
		}
	}
	if mgmtClientID == "" || mgmtClientSecret == "" {
		return "", fmt.Errorf("management client credentials required (--client-id and --client-secret, or management.* in config.yaml)")
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
		return "", err
	}
	token, _ := result["access_token"].(string)
	if token == "" {
		return "", fmt.Errorf("management token: %v", result["error_description"])
	}
	cachedManagementToken = token
	return token, nil
}

func apiGet(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	token, err := managementToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}

func apiPost(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	token, err := managementToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}
