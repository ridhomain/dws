package domain

import "time"

// AuthenticatedUserContext holds the validated and decrypted data from a company token.
// This information is added to the request context after successful token authentication.
type AuthenticatedUserContext struct {
	CompanyID string    `json:"company_id"`
	AgentID   string    `json:"agent_id"`
	UserID    string    `json:"user_id"`
	IsAdmin   bool      `json:"is_admin"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"-"` // Store the raw token for caching key generation, but don't marshal to JSON
}
