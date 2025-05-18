package middleware

import (
	"context"
	"errors"
	"net/http"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
)

const (
	apiKeyHeaderName = "X-API-Key"
	apiKeyQueryParam = "x-api-key" // As per FR-1
	tokenQueryParam  = "token"     // As per FR-1, FR-3 for CompanyTokenAuthMiddleware
)

// APIKeyAuthMiddleware creates a middleware for API key authentication.
// It checks for an API key in the request header (X-API-Key) or query parameter (x-api-key).
// If the key is missing or invalid, it returns a 401 Unauthorized error.
func APIKeyAuthMiddleware(cfgProvider config.Provider, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get(apiKeyHeaderName)
			if apiKey == "" {
				apiKey = r.URL.Query().Get(apiKeyQueryParam)
			}

			cfg := cfgProvider.Get()
			if cfg == nil || cfg.Auth.SecretToken == "" {
				logger.Error(r.Context(), "API key authentication failed: SecretToken not configured", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "API authentication cannot be performed.")
				errResp.WriteJSON(w, http.StatusInternalServerError)
				return
			}

			if apiKey == "" {
				logger.Warn(r.Context(), "API key authentication failed: Key missing", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInvalidAPIKey, "API key is required", "Provide API key in X-API-Key header or x-api-key query parameter.")
				errResp.WriteJSON(w, http.StatusUnauthorized)
				return
			}

			if apiKey != cfg.Auth.SecretToken {
				logger.Warn(r.Context(), "API key authentication failed: Invalid key", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInvalidAPIKey, "Invalid API key", "The provided API key is not valid.")
				errResp.WriteJSON(w, http.StatusUnauthorized)
				return
			}

			logger.Debug(r.Context(), "API key authentication successful", "path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// CompanyTokenAuthMiddleware creates a middleware for company token authentication.
// It extracts the 'token' query parameter, decrypts/validates it using AuthService,
// and injects AuthenticatedUserContext into the request context.
// This middleware should run AFTER APIKeyAuthMiddleware.
func CompanyTokenAuthMiddleware(authService *application.AuthService, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenValue := r.URL.Query().Get(tokenQueryParam) // Correctly get 'token'

			if tokenValue == "" {
				logger.Warn(r.Context(), "Company token authentication failed: 'token' query parameter missing", "path", r.URL.Path)
				// FR-3: Pre-upgrade failures return HTTP 403. ErrInvalidToken maps to 403.
				errResp := domain.NewErrorResponse(domain.ErrInvalidToken, "Company token is required", "Provide 'token' in query parameter.")
				errResp.WriteJSON(w, http.StatusForbidden)
				return
			}

			authCtx, err := authService.ProcessToken(r.Context(), tokenValue)
			if err != nil {
				logger.Warn(r.Context(), "Company token processing failed", "path", r.URL.Path, "error", err.Error())

				var errCode domain.ErrorCode
				var errMsg string
				// Default to the original error message for details, but can be overridden for client response.
				var errDetails string = err.Error()
				httpStatus := http.StatusForbidden // Default for token issues as per FR-3

				switch {
				case errors.Is(err, application.ErrTokenExpired):
					errCode = domain.ErrInvalidToken // As per Arch MD 10.3, ErrInvalidToken maps to 403/4403
					errMsg = "Company token has expired."
				case errors.Is(err, crypto.ErrTokenDecryptionFailed),
					errors.Is(err, application.ErrTokenPayloadInvalid),
					errors.Is(err, crypto.ErrInvalidTokenFormat),
					errors.Is(err, crypto.ErrCiphertextTooShort):
					errCode = domain.ErrInvalidToken
					errMsg = "Company token is invalid or malformed."
					// For security, don't leak crypto details to client in errDetails.
					// The logged err.Error() will have specifics.
					errDetails = "Token format or content error."
				case errors.Is(err, crypto.ErrInvalidAESKeySize), // This is a server config issue
					errors.New("application not configured for token decryption").Error() == err.Error(): // Check for specific string from AuthService
					errCode = domain.ErrInternal
					errMsg = "Server configuration error processing token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
				default:
					// For other unexpected errors from AuthService
					// (e.g. unhandled cache errors not ErrCacheMiss)
					logger.Error(r.Context(), "Unexpected internal error during token processing", "path", r.URL.Path, "detailed_error", err.Error())
					errCode = domain.ErrInternal
					errMsg = "An unexpected error occurred."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
				}

				errResp := domain.NewErrorResponse(errCode, errMsg, errDetails)
				errResp.WriteJSON(w, httpStatus)
				return
			}

			// Inject AuthenticatedUserContext into request context
			newReqCtx := context.WithValue(r.Context(), contextkeys.AuthUserContextKey, authCtx)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.CompanyIDKey, authCtx.CompanyID)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.AgentIDKey, authCtx.AgentID)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.UserIDKey, authCtx.UserID)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.IsAdminKey, authCtx.IsAdmin)

			logger.Debug(r.Context(), "Company token authentication successful",
				"path", r.URL.Path,
				"company_id", authCtx.CompanyID,
				"user_id", authCtx.UserID)
			next.ServeHTTP(w, r.WithContext(newReqCtx))
		})
	}
}
