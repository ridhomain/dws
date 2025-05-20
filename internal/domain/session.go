package domain

import (
	"context"
	"time"
)

// SessionLockManager defines the interface for managing distributed session locks.
type SessionLockManager interface {
	// AcquireLock attempts to acquire a lock for the given key with a specific value and TTL.
	// It returns true if the lock was acquired, false otherwise (e.g., lock already exists).
	AcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)

	// ReleaseLock attempts to release a lock for the given key, ensuring the value matches.
	// This is to prevent releasing a lock acquired by another instance.
	// Returns true if the lock was released by this call, false if the key didn't exist or value didn't match.
	ReleaseLock(ctx context.Context, key string, value string) (bool, error)

	// RefreshLock attempts to extend the TTL of an existing lock, ensuring the value matches.
	// Returns true if the lock was refreshed, false if the key didn't exist or value didn't match.
	RefreshLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)

	// ForceAcquireLock forcefully sets the lock for the given key with a specific value and TTL,
	// overwriting any existing lock. It should return true if the lock was set, false on error.
	ForceAcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)

	// RecordActivity records activity for the given key for a specified duration.
	RecordActivity(ctx context.Context, key string, activityTTL time.Duration) error
}

// KillSwitchMessage represents the payload sent over the session kill channel.
// For now, it's just the PodID of the new session that acquired the lock.
type KillSwitchMessage struct {
	NewPodID string `json:"new_pod_id"`
}

// KillSwitchPublisher defines the interface for publishing session kill messages.
type KillSwitchPublisher interface {
	PublishSessionKill(ctx context.Context, channel string, message KillSwitchMessage) error
}

// KillSwitchMessageHandler is a function type that will be called when a message is received on a subscribed channel.
type KillSwitchMessageHandler func(channel string, message KillSwitchMessage) error

// KillSwitchSubscriber defines the interface for subscribing to session kill messages.
type KillSwitchSubscriber interface {
	// SubscribeToSessionKillPattern subscribes to a pattern (e.g., "session_kill:*")
	// and calls the provided handler for each received message.
	// This method should likely run in a goroutine and handle reconnections.
	SubscribeToSessionKillPattern(ctx context.Context, pattern string, handler KillSwitchMessageHandler) error
	Close() error // To close the subscription
}
