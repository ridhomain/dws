package domain

import "time"

// AuthenticatedUserContext holds the validated and decrypted data from a company token.
// This information is added to the request context after successful token authentication.
type AuthenticatedUserContext struct {
	CompanyID string    `json:"company_id"`
	AgentID   string    `json:"agent_id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"-"` // Store the raw token for caching key generation, but don't marshal to JSON
}

// AdminUserContext holds the validated and decrypted data from an admin token.
// This information is added to the request context after successful admin token authentication.
// For now, we assume an admin might have a specific AdminID and potentially company scope.
type AdminUserContext struct {
	AdminID              string `json:"admin_id"`
	CompanyIDRestriction string `json:"company_id_restriction,omitempty"` // e.g., specific company ID or "*" for all
	// Fields for NATS subscription scope for agent events
	SubscribedCompanyID string    `json:"subscribed_company_id,omitempty"` // Specific company to subscribe for, or empty/"*" based on admin role
	SubscribedAgentID   string    `json:"subscribed_agent_id,omitempty"`   // Specific agent to subscribe for, or empty/"*"
	ExpiresAt           time.Time `json:"expires_at"`
	Token               string    `json:"-"` // Raw token for caching/logging
}
