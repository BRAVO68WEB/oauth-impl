package branding

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/oauth-impl/internal/config"
)

var errTooLarge = errors.New("asset exceeds 1MiB")

// AssetHandler serves one file from branding.assets_dir.
// The response CSP is stricter than the page CSP so an SVG opened on its own
// cannot run script. Callers that set a global CSP first still lose that
// header, because this handler replaces it before writing the body.
func AssetHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dir := ""
		if cfg != nil {
			dir = cfg.Branding.AssetsDir
		}
		if dir == "" {
			http.NotFound(w, r)
			return
		}
		f, ctype, err := openAsset(dir, chi.URLParam(r, "name"))
		if errors.Is(err, errTooLarge) {
			http.Error(w, "asset too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'none'; sandbox")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = io.Copy(w, f)
	}
}

// AssetExists reports whether name is a file the asset handler would serve.
func AssetExists(dir, name string) bool {
	f, _, err := openAsset(dir, name)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func openAsset(dir, name string) (*os.File, string, error) {
	if !safeAssetName(name) {
		return nil, "", os.ErrNotExist
	}
	ctype := config.BrandAssetType(name)
	if ctype == "" {
		return nil, "", os.ErrNotExist
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, "", err
	}
	full := filepath.Join(root, name)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, "", err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, "", os.ErrNotExist
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, "", err
	}
	if info.IsDir() {
		return nil, "", os.ErrNotExist
	}
	if info.Size() > config.MaxBrandAssetBytes {
		return nil, "", errTooLarge
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, "", err
	}
	return f, ctype, nil
}
