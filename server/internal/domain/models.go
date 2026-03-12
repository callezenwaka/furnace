package domain

import "time"

type User struct {
	ID          string         `json:"id"`
	Email       string         `json:"email"`
	DisplayName string         `json:"display_name"`
	Groups      []string       `json:"groups"`
	MFAMethod   string         `json:"mfa_method"`
	NextFlow    string         `json:"next_flow"`
	Claims      map[string]any `json:"claims,omitempty"`
	PhoneNumber string         `json:"phone_number,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	MemberIDs   []string  `json:"member_ids"`
	CreatedAt   time.Time `json:"created_at"`
}

type Flow struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	State     string    `json:"state"`
	Scenario  string    `json:"scenario,omitempty"`
	Attempts  int       `json:"attempts,omitempty"`
	Error     string    `json:"error,omitempty"`
	Protocol  string    `json:"protocol"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	FlowID    string    `json:"flow_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
