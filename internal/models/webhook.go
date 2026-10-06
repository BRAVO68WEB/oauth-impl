package models

import "time"

type Webhook struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Secret      string    `json:"secret,omitempty"`
	Events      []string  `json:"events"`
	Enabled     bool      `json:"enabled"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (w *Webhook) Wants(event string) bool {
	if w == nil || !w.Enabled {
		return false
	}
	for _, name := range w.Events {
		if name == "*" || name == event {
			return true
		}
	}
	return false
}
