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

// AdminTokenCacheAdapter implements domain.AdminTokenCacheStore using Redis.
// It stores AdminUserContext objects.
type AdminTokenCacheAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
}

// NewAdminTokenCacheAdapter creates a new AdminTokenCacheAdapter.
func NewAdminTokenCacheAdapter(redisClient *redis.Client, logger domain.Logger) *AdminTokenCacheAdapter {
	return &AdminTokenCacheAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}

// Get retrieves an AdminUserContext from the cache.
func (a *AdminTokenCacheAdapter) Get(ctx context.Context, key string) (*domain.AdminUserContext, error) {
	val, err := a.redisClient.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		a.logger.Debug(ctx, "Admin token cache miss", "key", key)
		return nil, application.ErrCacheMiss // Or return (nil, nil) if preferred
	}
	if err != nil {
		a.logger.Error(ctx, "Failed to get admin token from Redis cache", "key", key, "error", err.Error())
		return nil, fmt.Errorf("redis GET for admin token key '%s' failed: %w", key, err)
	}

	var adminCtx domain.AdminUserContext
	if err = json.Unmarshal([]byte(val), &adminCtx); err != nil {
		a.logger.Error(ctx, "Failed to unmarshal cached admin token data", "key", key, "error", err.Error())
		return nil, fmt.Errorf("failed to unmarshal admin token data for key '%s': %w", key, err)
	}
	a.logger.Debug(ctx, "Admin token cache hit", "key", key, "admin_id", adminCtx.AdminID)
	return &adminCtx, nil
}

// Set stores an AdminUserContext in the cache with a specific TTL.
func (a *AdminTokenCacheAdapter) Set(ctx context.Context, key string, value *domain.AdminUserContext, ttl time.Duration) error {
	payloadBytes, err := json.Marshal(value)
	if err != nil {
		a.logger.Error(ctx, "Failed to marshal admin token for caching", "key", key, "admin_id", value.AdminID, "error", err.Error())
		return fmt.Errorf("failed to marshal admin token for key '%s': %w", key, err)
	}

	if err = a.redisClient.Set(ctx, key, string(payloadBytes), ttl).Err(); err != nil {
		a.logger.Error(ctx, "Failed to set admin token in Redis cache", "key", key, "admin_id", value.AdminID, "error", err.Error())
		return fmt.Errorf("redis SET for admin token key '%s' failed: %w", key, err)
	}
	a.logger.Debug(ctx, "Successfully cached admin token", "key", key, "admin_id", value.AdminID, "ttl", ttl.String())
	return nil
}
