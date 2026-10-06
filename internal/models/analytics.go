package models

import "time"

type IPLoginStat struct {
	IP            string    `json:"ip"`
	Attempts      int       `json:"attempts"`
	Successes     int       `json:"successes"`
	Failures      int       `json:"failures"`
	MFA           int       `json:"mfa"`
	Users         int       `json:"users,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	LastUserAgent string    `json:"last_user_agent,omitempty"`
	New           bool      `json:"new"`
}

type DayLoginStat struct {
	Date      string `json:"date"`
	Successes int    `json:"successes"`
	Failures  int    `json:"failures"`
}

type LoginAnalytics struct {
	UserID      string         `json:"user_id,omitempty"`
	Window      string         `json:"window"`
	From        time.Time      `json:"from"`
	To          time.Time      `json:"to"`
	Attempts    int            `json:"attempts"`
	Successes   int            `json:"successes"`
	Failures    int            `json:"failures"`
	FailureRate float64        `json:"failure_rate"`
	UniqueIPs   int            `json:"unique_ips"`
	NewIPs      int            `json:"new_ips"`
	UniqueUsers int            `json:"unique_users,omitempty"`
	MFAAttempts int            `json:"mfa_attempts"`
	ByIP        []IPLoginStat  `json:"by_ip"`
	ByDay       []DayLoginStat `json:"by_day"`
}
