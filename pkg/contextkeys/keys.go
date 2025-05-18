package contextkeys

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey string

const (
	// RequestIDKey is the context key for storing and retrieving a request ID.
	RequestIDKey contextKey = "request_id"

	// EventIDKey is the context key for storing and retrieving an event ID.
	EventIDKey contextKey = "event_id"

	// UserIDKey is the context key for storing and retrieving a user ID from the token.
	UserIDKey contextKey = "user_id"

	// CompanyIDKey is the context key for storing and retrieving a company ID from the token.
	CompanyIDKey contextKey = "company_id"

	// AgentIDKey is the context key for storing and retrieving an agent ID from the token.
	AgentIDKey contextKey = "agent_id"

	// IsAdminKey is the context key for storing and retrieving the admin flag from the token.
	IsAdminKey contextKey = "is_admin"

	// AuthUserContextKey is the context key for storing the entire AuthenticatedUserContext struct.
	AuthUserContextKey contextKey = "auth_user_context"

	// Add other common context keys here as needed, for example:
	// TableNameKey contextKey = "table_name"
	// TraceIDKey contextKey = "trace_id"
	// SpanIDKey contextKey = "span_id"
)

// String makes contextKey satisfy fmt.Stringer to help with debugging/logging of keys themselves.
func (c contextKey) String() string {
	return string(c)
}
