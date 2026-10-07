package telemetry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTokenRequestSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(t.Context())
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"nope"}`)
	})
	server := httptest.NewServer(Middleware(mux))
	t.Cleanup(server.Close)

	response, err := http.PostForm(server.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"},
		"client_id":  {"app-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)

	spans := exp.GetSpans()
	var found *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "oauth.token" {
			found = &spans[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("spans = %v, want oauth.token", spanNames(spans))
	}
	attrs := map[string]string{}
	for _, attr := range found.Attributes {
		attrs[string(attr.Key)] = attr.Value.AsString()
	}
	if attrs["client_id"] != "app-1" {
		t.Fatalf("client_id = %q", attrs["client_id"])
	}
	if attrs["grant_type"] != "authorization_code" {
		t.Fatalf("grant_type = %q", attrs["grant_type"])
	}
	if attrs["oauth.error"] != "invalid_client" {
		t.Fatalf("oauth.error = %q", attrs["oauth.error"])
	}
}

func TestDisabledSetupIsNoop(t *testing.T) {
	shutdown, err := Setup(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func spanNames(spans []tracetest.SpanStub) []string {
	names := make([]string, len(spans))
	for i, span := range spans {
		names[i] = span.Name
	}
	return names
}
