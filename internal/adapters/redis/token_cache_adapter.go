package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application" // For application.ErrCacheMiss
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// TokenCacheAdapter implements the domain.TokenCacheStore interface using Redis
// for caching company user authentication tokens.
type TokenCacheAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
}

// NewTokenCacheAdapter creates a new instance of TokenCacheAdapter.
func NewTokenCacheAdapter(redisClient *redis.Client, logger domain.Logger) *TokenCacheAdapter {
	if redisClient == nil {
		// Panicking here because this is a critical setup error.
		// A nil logger would also be problematic, but redisClient is essential for functionality.
		panic("redisClient cannot be nil in NewTokenCacheAdapter")
	}
	if logger == nil {
		// This is also critical, but we might want to allow a fallback if absolutely necessary,
		// though best practice is to ensure a logger is always provided.
		panic("logger cannot be nil in NewTokenCacheAdapter")
	}
	return &TokenCacheAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}

// Get retrieves an AuthenticatedUserContext from the Redis cache.
func (a *TokenCacheAdapter) Get(ctx context.Context, key string) (*domain.AuthenticatedUserContext, error) {
	val, err := a.redisClient.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		a.logger.Debug(ctx, "Company token cache miss", "key", key)
		return nil, application.ErrCacheMiss // Use the application-defined error for cache miss
	}
	if err != nil {
		a.logger.Error(ctx, "Failed to get company token from Redis cache", "key", key, "error", err.Error())
		return nil, fmt.Errorf("redis GET for company token key '%s' failed: %w", key, err)
	}

	var userCtx domain.AuthenticatedUserContext
	if err = json.Unmarshal([]byte(val), &userCtx); err != nil {
		a.logger.Error(ctx, "Failed to unmarshal cached company token data", "key", key, "error", err.Error())
		return nil, fmt.Errorf("failed to unmarshal company token data for key '%s': %w", key, err)
	}

	// Optionally log more details from userCtx if needed for debugging, e.g., userCtx.UserID
	a.logger.Debug(ctx, "Company token cache hit", "key", key, "user_id", userCtx.UserID)
	return &userCtx, nil
}

// Set stores an AuthenticatedUserContext in the Redis cache with a specified TTL.
func (a *TokenCacheAdapter) Set(ctx context.Context, key string, value *domain.AuthenticatedUserContext, ttl time.Duration) error {
	payloadBytes, err := json.Marshal(value)
	if err != nil {
		a.logger.Error(ctx, "Failed to marshal company token for caching", "key", key, "user_id", value.UserID, "error", err.Error())
		return fmt.Errorf("failed to marshal company token for key '%s': %w", key, err)
	}

	if err = a.redisClient.Set(ctx, key, string(payloadBytes), ttl).Err(); err != nil {
		a.logger.Error(ctx, "Failed to set company token in Redis cache", "key", key, "user_id", value.UserID, "error", err.Error())
		return fmt.Errorf("redis SET for company token key '%s' failed: %w", key, err)
	}

	a.logger.Debug(ctx, "Successfully cached company token", "key", key, "user_id", value.UserID, "ttl", ttl.String())
	return nil
}
