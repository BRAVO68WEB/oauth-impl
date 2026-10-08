package mailer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderResetFromDirectory(t *testing.T) {
	dir := t.TempDir()
	body := "Subject: Reset {{.Username}}\nOpen {{.Link}} within {{.TTL}}.\n"
	if err := os.WriteFile(filepath.Join(dir, "reset.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject, text, err := Render(set, "reset", Data{Username: "ada", Link: "https://id.example/reset?token=abc", TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Reset ada" || text != "Open https://id.example/reset?token=abc within 1h.\n" {
		t.Fatalf("subject %q body %q", subject, text)
	}
	subject, text, err = Render(set, "verify", Data{Link: "https://id.example/verify-email?token=abc"})
	if err != nil {
		t.Fatal(err)
	}
	if subject != "Confirm your email" || text == "" {
		t.Fatalf("builtin verify subject %q body %q", subject, text)
	}
}

func TestLoadRejectsBrokenTemplate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "reset.txt"), []byte("no subject\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected a broken template to fail")
	}
}
