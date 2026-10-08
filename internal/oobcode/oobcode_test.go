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

func TestFromPaste(t *testing.T) {
	if got, err := FromPaste("  raw-code  ", "state", false); err != nil || got != "raw-code" {
		t.Fatalf("raw %q err=%v", got, err)
	}
	if _, err := FromPaste("   ", "state", false); err == nil {
		t.Fatal("expected an empty paste to fail")
	}
	combined, err := Combine("raw-code", "state")
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromPaste(combined, "state", true)
	if err != nil || got != "raw-code" {
		t.Fatalf("combined %q err=%v", got, err)
	}
	plain, err := FromPaste(combined, "state", false)
	if err != nil || plain != combined {
		t.Fatalf("unwrapped without the flag: %q err=%v", plain, err)
	}
	fromURL, err := FromPaste("https://issuer.example/cb?code=abc", "xyz", false)
	if err != nil || fromURL != "abc" {
		t.Fatalf("url %q err=%v", fromURL, err)
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
