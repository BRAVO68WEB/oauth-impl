package database

import "testing"

func TestRebindPostgresPlaceholders(t *testing.T) {
	got := rebind("postgres", "SELECT '?' AS q, a FROM t WHERE b = ? AND c = ?")
	want := "SELECT '?' AS q, a FROM t WHERE b = $1 AND c = $2"
	if got != want {
		t.Fatalf("rebind = %s", got)
	}
}

func TestRebindKeepsEscapedQuotes(t *testing.T) {
	got := rebind("postgres", "SELECT 'it''s ?' WHERE id = ?")
	want := "SELECT 'it''s ?' WHERE id = $1"
	if got != want {
		t.Fatalf("rebind = %s", got)
	}
}

func TestRebindSQLiteIsUnchanged(t *testing.T) {
	query := "SELECT * FROM t WHERE id = ?"
	if got := rebind("sqlite", query); got != query {
		t.Fatalf("rebind = %s", got)
	}
}
