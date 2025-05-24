package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// SessionLockManagerAdapter implements the domain.SessionLockManager interface using Redis.
// It requires a redis.Client to interact with the Redis server.
type SessionLockManagerAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger // For logging adapter-specific events
}

// NewSessionLockManagerAdapter creates a new instance of SessionLockManagerAdapter.
func NewSessionLockManagerAdapter(redisClient *redis.Client, logger domain.Logger) *SessionLockManagerAdapter {
	if redisClient == nil {
		// This should ideally not happen if DI is set up correctly, but as a safeguard:
		logger.Error(context.Background(), "Redis client is nil in NewSessionLockManagerAdapter", "error", "nil_redis_client")
		// Depending on desired strictness, could panic or return an error
	}
	return &SessionLockManagerAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}

// AcquireLock attempts to acquire a lock (SETNX behavior) for the given key with a specific value and TTL.
func (a *SessionLockManagerAdapter) AcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	// Log SETNX attempt with debug level
	a.logger.Debug(ctx, "Attempting Redis SETNX lock acquisition",
		"key", key,
		"value", value,
		"ttl", ttl.String(),
		"operation", "AcquireLock")

	// Try to get the current value before attempting SETNX to provide context on failures
	currentVal, getErr := a.redisClient.Get(ctx, key).Result()
	if getErr != nil && getErr != redis.Nil {
		a.logger.Debug(ctx, "Failed to retrieve current key value before SETNX",
			"key", key,
			"error", getErr.Error(),
			"operation", "AcquireLock")
	} else if getErr == redis.Nil {
		a.logger.Debug(ctx, "Key does not exist before SETNX attempt",
			"key", key,
			"operation", "AcquireLock")
	} else {
		a.logger.Debug(ctx, "Key already exists with value before SETNX attempt",
			"key", key,
			"current_value", currentVal,
			"attempted_value", value,
			"operation", "AcquireLock")
	}

	// Perform the actual SETNX operation
	acquired, err := a.redisClient.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		a.logger.Error(ctx, "Redis SETNX failed", "key", key, "error", err.Error())
		return false, fmt.Errorf("redis SETNX for key '%s' failed: %w", key, err)
	}

	// Log detailed result
	if acquired {
		a.logger.Info(ctx, "Redis SETNX result", "key", key, "value", value, "ttl", ttl, "acquired", acquired)
		a.logger.Debug(ctx, "Successfully acquired lock with SETNX",
			"key", key,
			"value", value,
			"ttl", ttl.String(),
			"operation", "AcquireLock")
	} else {
		// If we failed to acquire, check if it's because someone else has the lock
		currentVal, getErr := a.redisClient.Get(ctx, key).Result()
		if getErr != nil && getErr != redis.Nil {
			a.logger.Debug(ctx, "Failed to retrieve existing lock holder after failed SETNX",
				"key", key,
				"error", getErr.Error(),
				"operation", "AcquireLock")
		} else if getErr == redis.Nil {
			a.logger.Debug(ctx, "Lock key disappeared between SETNX attempt and value check",
				"key", key,
				"operation", "AcquireLock")
		} else {
			a.logger.Debug(ctx, "Failed to acquire lock, key held by different pod",
				"key", key,
				"current_holder", currentVal,
				"attempted_value", value,
				"operation", "AcquireLock")
		}
		a.logger.Info(ctx, "Redis SETNX result", "key", key, "value", value, "ttl", ttl, "acquired", acquired)
	}

	return acquired, nil
}

// ReleaseLock attempts to release a lock for the given key, only if the value matches.
// This uses a Lua script to ensure atomicity of the GET and DEL operations.
func (a *SessionLockManagerAdapter) ReleaseLock(ctx context.Context, key string, value string) (bool, error) {
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`
	result, err := a.redisClient.Eval(ctx, script, []string{key}, value).Int64()
	if err != nil && !errors.Is(err, redis.Nil) { // redis.Nil is not an error if key simply doesn't exist
		a.logger.Error(ctx, "Redis EVAL (ReleaseLock script) failed", "key", key, "value", value, "error", err.Error())
		return false, fmt.Errorf("redis EVAL for ReleaseLock on key '%s' failed: %w", key, err)
	}

	released := result == 1
	a.logger.Info(ctx, "Redis ReleaseLock result", "key", key, "value", value, "released_by_script", released, "script_result_val", result)
	return released, nil
}

// RefreshLock attempts to extend the TTL of an existing lock, only if the value matches.
// This uses a Lua script to ensure atomicity.
func (a *SessionLockManagerAdapter) RefreshLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	// Debug logging before attempting TTL refresh
	a.logger.Debug(ctx, "Attempting to refresh lock TTL",
		"key", key,
		"value", value,
		"new_ttl", ttl.String(),
		"operation", "RefreshLock")

	// Check if the key exists and what its current value is before refresh
	currentVal, getErr := a.redisClient.Get(ctx, key).Result()
	if getErr != nil && !errors.Is(getErr, redis.Nil) {
		a.logger.Debug(ctx, "Error checking current lock value before refresh",
			"key", key,
			"error", getErr.Error(),
			"operation", "RefreshLock")
	} else if errors.Is(getErr, redis.Nil) {
		a.logger.Debug(ctx, "Lock key does not exist during refresh attempt",
			"key", key,
			"attempted_value", value,
			"operation", "RefreshLock")
	} else {
		// Key exists - check if we are the owner
		if currentVal == value {
			a.logger.Debug(ctx, "Current lock is owned by this pod, proceeding with refresh",
				"key", key,
				"current_value", currentVal,
				"operation", "RefreshLock")
		} else {
			a.logger.Debug(ctx, "Lock is owned by a different pod, refresh will fail",
				"key", key,
				"current_value", currentVal,
				"attempted_value", value,
				"operation", "RefreshLock")
		}
	}

	// Attempt the actual TTL refresh with Lua script
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("expire", KEYS[1], ARGV[2])
		else
			return 0
		end
	`
	ttlSeconds := int64(ttl.Seconds())
	result, err := a.redisClient.Eval(ctx, script, []string{key}, value, ttlSeconds).Int64()

	if err != nil && !errors.Is(err, redis.Nil) { // redis.Nil is not an error if key simply doesn't exist
		a.logger.Error(ctx, "Redis EVAL (RefreshLock script) failed", "key", key, "value", value, "error", err.Error())
		return false, fmt.Errorf("redis EVAL for RefreshLock on key '%s' failed: %w", key, err)
	}

	refreshed := result == 1

	// More detailed debug logs based on result
	if refreshed {
		a.logger.Debug(ctx, "Successfully refreshed lock TTL",
			"key", key,
			"value", value,
			"new_ttl_seconds", ttlSeconds,
			"operation", "RefreshLock")
	} else {
		// Check why refresh failed - either key doesn't exist or value doesn't match
		currentVal, getErr := a.redisClient.Get(ctx, key).Result()
		if getErr != nil && !errors.Is(getErr, redis.Nil) {
			a.logger.Debug(ctx, "Error checking key after failed refresh",
				"key", key,
				"error", getErr.Error(),
				"operation", "RefreshLock")
		} else if errors.Is(getErr, redis.Nil) {
			a.logger.Debug(ctx, "Lock refresh failed: key no longer exists",
				"key", key,
				"operation", "RefreshLock")
		} else if currentVal != value {
			a.logger.Debug(ctx, "Lock refresh failed: key owned by different pod",
				"key", key,
				"current_value", currentVal,
				"attempted_value", value,
				"operation", "RefreshLock")
		} else {
			a.logger.Debug(ctx, "Lock refresh failed for unknown reason despite matching value",
				"key", key,
				"current_value", currentVal,
				"attempted_value", value,
				"operation", "RefreshLock")
		}
	}

	a.logger.Info(ctx, "Redis RefreshLock result", "key", key, "value", value, "ttl_seconds", ttlSeconds, "refreshed_by_script", refreshed, "script_result_val", result)
	return refreshed, nil
}

// ForceAcquireLock forcefully sets the lock for the given key with a specific value and TTL (SET behavior).
func (a *SessionLockManagerAdapter) ForceAcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	_, err := a.redisClient.Set(ctx, key, value, ttl).Result()
	if err != nil {
		a.logger.Error(ctx, "Redis SET failed for ForceAcquireLock", "key", key, "error", err.Error())
		return false, fmt.Errorf("redis SET for key '%s' in ForceAcquireLock failed: %w", key, err)
	}
	a.logger.Info(ctx, "Redis SET successful for ForceAcquireLock", "key", key, "value", value, "ttl", ttl)
	return true, nil
}

func (a *SessionLockManagerAdapter) RecordActivity(ctx context.Context, key string, activityTTL time.Duration) error {
	activityKey := key + ":last_active"
	now := time.Now().Unix()
	err := a.redisClient.Set(ctx, activityKey, now, activityTTL).Err()
	if err != nil {
		a.logger.Error(ctx, "Redis SET failed for RecordActivity", "key", activityKey, "error", err.Error())
		return fmt.Errorf("redis SET for key '%s' in RecordActivity failed: %w", activityKey, err)
	}
	a.logger.Debug(ctx, "Redis SET successful for RecordActivity", "key", activityKey, "timestamp", now, "ttl", activityTTL)
	return nil
}
