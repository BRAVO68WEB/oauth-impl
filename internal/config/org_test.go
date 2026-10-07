package config

import "testing"

func TestOrgFlagsDefaultOff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Org.Enabled || cfg.Org.EnabledDomainBasedAutolookup {
		t.Fatalf("org flags = %+v", cfg.Org)
	}
}

func TestDomainAutolookupRequiresOrgs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Org.EnabledDomainBasedAutolookup = true
	if err := ValidatePlatform(cfg); err == nil {
		t.Fatal("expected validation error")
	}
	cfg.Org.Enabled = true
	if err := ValidatePlatform(cfg); err != nil {
		t.Fatal(err)
	}
}
