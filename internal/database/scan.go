package database

import "fmt"

func bitArg(v bool) int {
	if v {
		return 1
	}
	return 0
}

// flag scans an INTEGER 0/1 column from SQLite or Postgres.
type flag int

func (f *flag) Scan(src any) error {
	switch v := src.(type) {
	case bool:
		if v {
			*f = 1
		} else {
			*f = 0
		}
	case int64:
		*f = flag(v)
	case int32:
		*f = flag(v)
	case int:
		*f = flag(v)
	case []byte:
		if string(v) == "1" || string(v) == "t" || string(v) == "true" {
			*f = 1
		}
	case string:
		if v == "1" || v == "t" || v == "true" {
			*f = 1
		}
	case nil:
		*f = 0
	default:
		return fmt.Errorf("cannot scan %T into flag", src)
	}
	return nil
}

func (f flag) Bool() bool { return f != 0 }
