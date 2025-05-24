package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid" // For generating UUIDs
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
)

const XRequestIDHeader = "X-Request-ID"

// RequestIDMiddleware injects a request ID into the context.
// It tries to get it from the X-Request-ID header, otherwise generates a new UUID.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(XRequestIDHeader)
		if requestID == "" {
			requestID = uuid.NewString()
		}

		ctx := context.WithValue(r.Context(), contextkeys.RequestIDKey, requestID)
		w.Header().Set(XRequestIDHeader, requestID) // Also set it in the response header
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
