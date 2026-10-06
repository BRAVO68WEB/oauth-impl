package database

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
)

// rebind turns `?` placeholders into `$1`, `$2`, … for Postgres.
// A question mark inside a single-quoted string stays a question mark.
func rebind(driver, query string) string {
	if driver != "postgres" {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	inQuote := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '\'' {
			if inQuote && i+1 < len(query) && query[i+1] == '\'' {
				b.WriteByte(c)
				b.WriteByte(query[i+1])
				i++
				continue
			}
			inQuote = !inQuote
			b.WriteByte(c)
			continue
		}
		if c == '?' && !inQuote {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func (db *DB) prepare(query string) string {
	if db != nil && db.driver == "postgres" {
		query = strings.ReplaceAll(query, "DATETIME", "TIMESTAMPTZ")
	}
	driver := "sqlite"
	if db != nil && db.driver != "" {
		driver = db.driver
	}
	return rebind(driver, query)
}

func newID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
