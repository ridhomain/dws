package domain

import (
	"context"

	"github.com/coder/websocket"
)

// ManagedConnection represents an active WebSocket connection managed by the system.
// It defines the essential operations needed by other parts of the application,
// like the ConnectionManager, to manage and interact with an established connection.
type ManagedConnection interface {
	// Close attempts to close the WebSocket connection with a specified status code and reason.
	Close(statusCode websocket.StatusCode, reason string) error

	// WriteJSON sends a JSON-encoded message to the client.
	WriteJSON(v interface{}) error

	// RemoteAddr returns the remote network address string of the client.
	RemoteAddr() string

	// Context returns the context associated with this specific connection.
	// This context may contain connection-specific logging information like request_id.
	Context() context.Context

	// GetCurrentChatID returns the current chat ID associated with this connection.
	GetCurrentChatID() string
}
