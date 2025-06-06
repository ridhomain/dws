package middleware

import (
	"context"
	"errors"
	"net/http"

	"strings"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
)

// AdminAPIKeyAuthMiddleware creates a middleware for admin API key authentication.
// It checks for the dedicated AdminSecretToken in the X-API-Key header.
func AdminAPIKeyAuthMiddleware(cfgProvider config.Provider, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminApiKey := r.Header.Get(apiKeyHeaderName) // Re-use constant from auth.go

			// Add query parameter fallback for WebSocket connections
			if adminApiKey == "" {
				adminApiKey = r.URL.Query().Get(apiKeyQueryParam) // "x-api-key"
			}

			cfg := cfgProvider.Get()
			if cfg == nil || cfg.Auth.AdminSecretToken == "" {
				logger.Error(r.Context(), "Admin auth failed: AdminSecretToken not configured", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Admin auth cannot be performed.")
				errResp.WriteJSON(w, http.StatusInternalServerError)
				return
			}

			if adminApiKey == "" {
				logger.Warn(r.Context(), "Admin auth failed: Admin key missing", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrUnauthorized, "Admin API key is required", "Provide admin API key in X-API-Key header or x-api-key query parameter.")
				errResp.WriteJSON(w, http.StatusUnauthorized)
				return
			}

			if adminApiKey != cfg.Auth.AdminSecretToken {
				logger.Warn(r.Context(), "Admin auth failed: Invalid admin key", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrForbidden, "Invalid admin API key", "The provided admin API key is not valid.")
				errResp.WriteJSON(w, http.StatusForbidden)
				return
			}

			logger.Debug(r.Context(), "Admin API key authentication successful", "path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

const (
	adminTokenQueryParam = "token" // Using "token" as per FR-ADMIN-1. Consistent with company token.
)

// AdminAuthMiddleware creates a middleware for admin token authentication for WebSocket connections.
// It extracts the 'token' query parameter, decrypts/validates it using AuthService.ProcessAdminToken,
// and injects AdminUserContext into the request context.
// This middleware should run AFTER APIKeyAuthMiddleware.
func AdminAuthMiddleware(authService *application.AuthService, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenValue := r.URL.Query().Get(adminTokenQueryParam)
			if tokenValue == "" {
				logger.Warn(r.Context(), "Admin token authentication failed: 'token' query parameter missing", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInvalidToken, "Admin token is required", "Provide 'token' in query parameter.")
				errResp.WriteJSON(w, http.StatusForbidden) // FR-ADMIN-1 implies pre-upgrade failures return appropriate HTTP error
				return
			}

			adminCtx, err := authService.ProcessAdminToken(r.Context(), tokenValue)
			if err != nil {
				logger.Warn(r.Context(), "Admin token processing failed", "path", r.URL.Path, "error", err.Error())
				var errCode domain.ErrorCode
				var errMsg string
				var errDetails string = err.Error()
				httpStatus := http.StatusForbidden
				var reasonForMetric string = "unknown_error"

				switch {
				case errors.Is(err, application.ErrTokenExpired):
					errCode = domain.ErrInvalidToken
					errMsg = "Admin token has expired."
					reasonForMetric = "expired"
				case errors.Is(err, crypto.ErrTokenDecryptionFailed),
					errors.Is(err, application.ErrTokenPayloadInvalid),
					errors.Is(err, crypto.ErrInvalidTokenFormat),
					errors.Is(err, crypto.ErrCiphertextTooShort):
					errCode = domain.ErrInvalidToken
					errMsg = "Admin token is invalid or malformed."
					errDetails = "Token format or content error."
					reasonForMetric = "invalid_format_or_content"
				case errors.Is(err, crypto.ErrInvalidAESKeySize),
					strings.Contains(err.Error(), "application not configured for admin token decryption"):
					errCode = domain.ErrInternal
					errMsg = "Server configuration error processing admin token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
					reasonForMetric = "config_error_aes_key"
				default:
					logger.Error(r.Context(), "Unexpected internal error during admin token processing", "path", r.URL.Path, "detailed_error", err.Error())
					errCode = domain.ErrInternal
					errMsg = "An unexpected error occurred while processing admin token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
					reasonForMetric = "internal_server_error"
				}
				metrics.IncrementAuthFailure("admin", reasonForMetric)
				domain.NewErrorResponse(errCode, errMsg, errDetails).WriteJSON(w, httpStatus)
				return
			}
			metrics.IncrementAuthSuccess("admin")
			newReqCtx := context.WithValue(r.Context(), contextkeys.AdminUserContextKey, adminCtx)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.UserIDKey, adminCtx.AdminID) // For consistent logging if UserIDKey is used generally
			logger.Debug(r.Context(), "Admin token authentication successful",
				"path", r.URL.Path,
				"admin_id", adminCtx.AdminID,
				"company_restriction", adminCtx.CompanyIDRestriction)
			next.ServeHTTP(w, r.WithContext(newReqCtx))
		})
	}
}
