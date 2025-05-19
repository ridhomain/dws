package middleware

import (
	"net/http"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// TokenGenerationAuthMiddleware creates a middleware for the /generate-token endpoint.
// It checks for the dedicated TokenGenerationAdminKey in the X-API-Key header.
func TokenGenerationAuthMiddleware(cfgProvider config.Provider, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminApiKey := r.Header.Get(apiKeyHeaderName) // Re-use constant from auth.go

			cfg := cfgProvider.Get()
			if cfg == nil || cfg.Auth.TokenGenerationAdminKey == "" {
				logger.Error(r.Context(), "Token generation auth failed: TokenGenerationAdminKey not configured", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Token generation auth cannot be performed.")
				errResp.WriteJSON(w, http.StatusInternalServerError)
				return
			}

			if adminApiKey == "" {
				logger.Warn(r.Context(), "Token generation auth failed: Admin key missing", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrUnauthorized, "Admin API key is required", "Provide admin API key in X-API-Key header.") // Assuming ErrUnauthorized exists
				errResp.WriteJSON(w, http.StatusUnauthorized)
				return
			}

			if adminApiKey != cfg.Auth.TokenGenerationAdminKey {
				logger.Warn(r.Context(), "Token generation auth failed: Invalid admin key", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrForbidden, "Invalid admin API key", "The provided admin API key is not valid.") // Assuming ErrForbidden exists for this
				errResp.WriteJSON(w, http.StatusForbidden)
				return
			}

			logger.Debug(r.Context(), "Token generation admin key authentication successful", "path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}
