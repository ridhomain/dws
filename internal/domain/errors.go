package domain

import (
	"encoding/json"
	"net/http"

	"github.com/coder/websocket"
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
	ErrMethodNotAllowed    ErrorCode = "E4005"               // For HTTP 405 Method Not Allowed

	// General Authentication/Authorization Errors
	ErrUnauthorized ErrorCode = "E4001" // HTTP 401, general unauthorized
	ErrForbidden    ErrorCode = "E4003" // HTTP 403, general forbidden (re-using E4003 if suitable or make new)
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

	// If status code is 0 or not provided explicitly, use the mapping function
	if httpStatusCode <= 0 {
		httpStatusCode = er.ToHTTPStatus()
	}

	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(er) // Best effort, error from Encode is not typically handled here.
}

// ToWebSocketCloseCode converts an ErrorCode to the appropriate WebSocket close code.
func (er ErrorResponse) ToWebSocketCloseCode() websocket.StatusCode {
	switch er.Code {
	case ErrInvalidAPIKey:
		return websocket.StatusCode(4401)
	case ErrInvalidToken, ErrUnauthorized, ErrForbidden:
		return websocket.StatusCode(4403)
	case ErrSessionConflict:
		return websocket.StatusCode(4402)
	case ErrRateLimitExceeded:
		return websocket.StatusCode(4429)
	case ErrBadRequest, ErrMethodNotAllowed:
		return websocket.StatusCode(4400)
	case ErrInternal, ErrSubscriptionFailure:
		return websocket.StatusCode(1011)
	default:
		return websocket.StatusCode(1011) // Internal Server Error for any unhandled case
	}
}

// ToHTTPStatus converts an ErrorCode to the appropriate HTTP status code.
func (er ErrorResponse) ToHTTPStatus() int {
	switch er.Code {
	case ErrInvalidAPIKey, ErrUnauthorized:
		return http.StatusUnauthorized // 401
	case ErrInvalidToken, ErrForbidden:
		return http.StatusForbidden // 403
	case ErrSessionConflict:
		return http.StatusConflict // 409
	case ErrRateLimitExceeded:
		return http.StatusTooManyRequests // 429
	case ErrBadRequest:
		return http.StatusBadRequest // 400
	case ErrMethodNotAllowed:
		return http.StatusMethodNotAllowed // 405
	case ErrInternal, ErrSubscriptionFailure:
		return http.StatusInternalServerError // 500
	default:
		return http.StatusInternalServerError // 500 for any unhandled case
	}
}
