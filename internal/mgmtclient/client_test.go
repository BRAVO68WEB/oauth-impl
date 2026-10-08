package mgmtclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetSetsBearer(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-1"})
			return
		}
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	client := &Client{
		ServerURL:    srv.URL,
		ClientID:     "mgmt",
		ClientSecret: "secret",
		ConfigPath:   filepath.Join(t.TempDir(), "missing.yaml"),
	}
	resp, err := client.Get(srv.URL + "/api/users")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got != "Bearer tok-1" {
		t.Fatalf("authorization %q", got)
	}
}
