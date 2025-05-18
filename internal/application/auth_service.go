package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)

var (
	ErrTokenPayloadInvalid = errors.New("token payload is invalid")
	ErrTokenExpired        = errors.New("token has expired")
	ErrCacheMiss           = errors.New("token not found in cache") // Specific error for cache miss
)

// AuthService handles token decryption, validation, and caching.
// For now, it only contains parsing and validation logic.
type AuthService struct {
	logger domain.Logger
	config config.Provider
	cache  domain.TokenCacheStore
}

// NewAuthService creates a new AuthService.
func NewAuthService(logger domain.Logger, config config.Provider, cache domain.TokenCacheStore) *AuthService {
	if logger == nil {
		panic("logger is nil in NewAuthService") // Or use a default no-op logger
	}
	if config == nil {
		panic("config provider is nil in NewAuthService")
	}
	if cache == nil {
		panic("cache store is nil in NewAuthService")
	}
	return &AuthService{
		logger: logger,
		config: config,
		cache:  cache,
	}
}

// ParseAndValidateDecryptedToken parses the decrypted token data, validates it,
// and populates an AuthenticatedUserContext struct.
// rawTokenB64 is the original base64 encoded token, used for caching key generation later.
func (s *AuthService) ParseAndValidateDecryptedToken(decryptedPayload []byte, rawTokenB64 string) (*domain.AuthenticatedUserContext, error) {
	var ctx domain.AuthenticatedUserContext
	err := json.Unmarshal(decryptedPayload, &ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal token JSON: %v", ErrTokenPayloadInvalid, err)
	}

	// Basic validation for essential fields (can be expanded)
	if ctx.CompanyID == "" || ctx.AgentID == "" || ctx.UserID == "" || ctx.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: missing essential fields (company_id, agent_id, user_id, expires_at)", ErrTokenPayloadInvalid)
	}

	if time.Now().After(ctx.ExpiresAt) {
		return nil, fmt.Errorf("%w: token expired at %v", ErrTokenExpired, ctx.ExpiresAt)
	}

	ctx.Token = rawTokenB64 // Store the raw token for caching purposes

	return &ctx, nil
}

// ProcessToken attempts to retrieve a validated token from cache.
// If not found, it decrypts, validates, and then caches the token.
func (s *AuthService) ProcessToken(reqCtx context.Context, tokenB64 string) (*domain.AuthenticatedUserContext, error) {
	cacheKey := rediskeys.TokenCacheKey(tokenB64)

	// 1. Try to get from cache
	cachedCtx, err := s.cache.Get(reqCtx, cacheKey)
	if err == nil && cachedCtx != nil {
		// Cache hit, ensure it's not expired (though Redis TTL should handle this, defensive check)
		if time.Now().After(cachedCtx.ExpiresAt) {
			s.logger.Warn(reqCtx, "Cached token found but was expired", "cache_key", cacheKey, "expires_at", cachedCtx.ExpiresAt)
			// Treat as cache miss, proceed to decrypt and validate
		} else {
			s.logger.Debug(reqCtx, "Token found in cache and is valid", "cache_key", cacheKey)
			return cachedCtx, nil
		}
	} else if err != nil && !errors.Is(err, ErrCacheMiss) { // Allow custom ErrCacheMiss or (nil,nil) for cache miss
		// Log error if it's not a simple cache miss
		s.logger.Error(reqCtx, "Error retrieving token from cache", "cache_key", cacheKey, "error", err.Error())
		// Proceed to decrypt, as cache is unreliable or errored
	}

	s.logger.Debug(reqCtx, "Token not found in cache or cache error, proceeding to decrypt", "cache_key", cacheKey)

	// 2. If cache miss or error, decrypt and validate
	aesKeyHex := s.config.Get().Auth.TokenAESKey
	if aesKeyHex == "" {
		s.logger.Error(reqCtx, "TOKEN_AES_KEY not configured", "config_key", "auth.token_aes_key")
		return nil, errors.New("application not configured for token decryption")
	}

	decryptedPayload, err := crypto.DecryptAESGCM(aesKeyHex, tokenB64)
	if err != nil {
		s.logger.Warn(reqCtx, "Token decryption failed", "error", err.Error())
		return nil, err // err is already descriptive (e.g., crypto.ErrTokenDecryptionFailed)
	}

	validatedCtx, err := s.ParseAndValidateDecryptedToken(decryptedPayload, tokenB64)
	if err != nil {
		s.logger.Warn(reqCtx, "Decrypted token failed validation", "error", err.Error())
		return nil, err
	}

	// 3. Cache the successfully validated token
	cacheTTLSeconds := s.config.Get().Auth.TokenCacheTTLSeconds
	cacheTTL := time.Duration(cacheTTLSeconds) * time.Second

	if cacheTTLSeconds == 0 { // Default if not set or zero from config
		cacheTTL = 30 * time.Second // Default to 30 seconds as per spec
		s.logger.Debug(reqCtx, "auth.tokenCacheTTLSeconds not configured or zero, using default 30s", "cache_key", cacheKey)
	}

	if err := s.cache.Set(reqCtx, cacheKey, validatedCtx, cacheTTL); err != nil {
		s.logger.Error(reqCtx, "Failed to cache validated token", "cache_key", cacheKey, "error", err.Error())
		// Non-fatal error for caching, proceed with the validated context
	}
	s.logger.Info(reqCtx, "Token decrypted, validated, and cached successfully", "cache_key", cacheKey)
	return validatedCtx, nil
}
