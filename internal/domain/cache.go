package domain

import (
	"context"
	"time"
)

// TokenCacheStore defines the interface for caching validated authenticated user contexts.
type TokenCacheStore interface {
	// Get retrieves an AuthenticatedUserContext from the cache.
	// If the item is not found, it should return (nil, nil) or (nil, ErrCacheMiss).
	Get(ctx context.Context, key string) (*AuthenticatedUserContext, error)

	// Set stores an AuthenticatedUserContext in the cache with a specific TTL.
	Set(ctx context.Context, key string, value *AuthenticatedUserContext, ttl time.Duration) error
}

// AdminTokenCacheStore defines the interface for caching validated admin user contexts.
type AdminTokenCacheStore interface {
	Get(ctx context.Context, key string) (*AdminUserContext, error)
	Set(ctx context.Context, key string, value *AdminUserContext, ttl time.Duration) error
}

// Consider adding a specific error for cache miss if not relying on (nil, nil)
// var ErrCacheMiss = errors.New("item not found in cache")
