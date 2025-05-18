package domain

import (
	"encoding/json"
	"net/http"
)

// ErrorCode represents a specific error condition.
type ErrorCode string

const (
	ErrInvalidAPIKey       ErrorCode = "InvalidAPIKey"       // HTTP 401, WS Close 4401
	ErrInvalidToken        ErrorCode = "InvalidToken"        // HTTP 403, WS Close 4403
	ErrSessionConflict     ErrorCode = "SessionConflict"     // WS Close 4402
	ErrSubscriptionFailure ErrorCode = "SubscriptionFailure" // Internal, potentially WS Close 1011
	ErrRateLimitExceeded   ErrorCode = "RateLimitExceeded"   // WS Close 4429 (custom) or HTTP 429
	ErrBadRequest          ErrorCode = "BadRequest"          // HTTP 400, e.g., invalid select_chat payload
	ErrInternal            ErrorCode = "InternalServerError" // HTTP 500, WS Close 1011
)

// ErrorResponse is the standard error format returned to clients via WebSocket or HTTP JSON.
// For WebSocket, this might be part of a larger message, e.g., {"type": "error", "payload": ErrorResponseObject}.
type ErrorResponse struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
}

// NewErrorResponse creates a new ErrorResponse struct.
func NewErrorResponse(code ErrorCode, message string, details string) ErrorResponse {
	return ErrorResponse{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// WriteJSON sends an ErrorResponse as JSON with the given HTTP status code.
func (er ErrorResponse) WriteJSON(w http.ResponseWriter, httpStatusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(er) // Best effort, error from Encode is not typically handled here.
}
