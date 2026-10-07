package config

import "testing"

func TestTelemetryDisabledByDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Telemetry.Enabled {
		t.Fatal("telemetry is on by default")
	}
}

func TestTelemetryRequiresEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Telemetry.Enabled = true
	cfg.Telemetry.OTLPEndpoint = ""
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err == nil {
		t.Fatal("expected endpoint error")
	}
	cfg.Telemetry.OTLPEndpoint = "localhost:4318"
	cfg.Telemetry.SampleRatio = 2
	if err := ValidatePlatform(cfg); err == nil {
		t.Fatal("expected sample ratio error")
	}
}
