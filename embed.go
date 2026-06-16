package oauthimpl

import "embed"

//go:embed openapi/spec.yaml
var OpenAPISpec []byte

//go:embed internal/templates/*.html
var TemplateFS embed.FS
