package oobcode

import "testing"

func TestCombineAndRecover(t *testing.T) {
	combined, err := Combine("auth-code-1", "state-value-1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Recover(combined, "state-value-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "auth-code-1" {
		t.Fatalf("code %q", got)
	}
	if _, err := Recover(combined, "other-state"); err == nil {
		t.Fatal("expected a checksum mismatch for a different state")
	}
	if _, err := Recover("abcd", "state-value-1"); err == nil {
		t.Fatal("expected a short value to fail")
	}
}

func TestFromPasteAcceptsHelperURL(t *testing.T) {
	got, err := FromPaste("https://issuer.example/oauth/oob?code=abc&state=xyz", "xyz", true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Fatalf("code %q", got)
	}
	if _, err := FromPaste("https://issuer.example/oauth/oob?code=abc&state=nope", "xyz", true); err == nil {
		t.Fatal("expected a state mismatch")
	}
}
