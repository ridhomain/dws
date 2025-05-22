package application

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)

const (
	maxSessionLockRetries   = 3
	initialLockRetryDelayMs = 50
	maxLockRetryDelayMs     = 500
	lockForceAcquireDelayMs = 100 // Additional delay before a final force acquire if all retries fail
)

// SessionLocker returns the underlying session lock manager.
// This is used by the WebSocket handler to release locks upon connection failure or closure.
func (cm *ConnectionManager) SessionLocker() domain.SessionLockManager {
	return cm.sessionLocker
}

// AcquireSessionLockOrNotify attempts to acquire a distributed lock for a new user session.
// If the lock is already held, it publishes a notification to the kill switch channel.
func (cm *ConnectionManager) AcquireSessionLockOrNotify(ctx context.Context, companyID, agentID, userID string) (bool, error) {
	cfg := cm.configProvider.Get()
	podID := cfg.Server.PodID
	if podID == "" {
		cm.logger.Error(ctx, "PodID is not configured. Session locking/notification will not work correctly.", "operation", "AcquireSessionLockOrNotify")
		return false, fmt.Errorf("podID is not configured")
	}

	sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second

	cm.logger.Info(ctx, "Attempting to acquire session lock",
		"sessionKey", sessionKey,
		"podID", podID,
		"ttlSeconds", sessionTTL.Seconds(),
	)

	cm.logger.Debug(ctx, "Session lock acquisition details",
		"sessionKey", sessionKey,
		"podID", podID,
		"ttlSeconds", sessionTTL.Seconds(),
		"companyID", companyID,
		"agentID", agentID,
		"userID", userID,
		"operation", "AcquireSessionLockOrNotify")

	metrics.IncrementSessionLockAttempts("user", "initial_setnx")
	acquired, err := cm.sessionLocker.AcquireLock(ctx, sessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire session lock from store (initial attempt)",
			"error", err.Error(),
			"sessionKey", sessionKey,
		)
		metrics.IncrementSessionLockFailure("user", "redis_error_initial")
		return false, fmt.Errorf("failed to acquire session lock: %w", err)
	}

	if acquired {
		cm.logger.Info(ctx, "Session lock acquired successfully (initial attempt)",
			"sessionKey", sessionKey,
			"podID", podID,
		)
		cm.logger.Debug(ctx, "Initial SETNX for session lock succeeded",
			"sessionKey", sessionKey,
			"podID", podID,
			"ttlSeconds", sessionTTL.Seconds(),
			"operation", "AcquireSessionLockOrNotify")
		metrics.IncrementSessionLockSuccess("user", "initial_setnx")
		return true, nil
	}

	// Lock not acquired on first attempt, publish kill message and start retry logic
	cm.logger.Warn(ctx, "Failed to acquire session lock (already held). Publishing kill message and starting retry logic.",
		"sessionKey", sessionKey,
		"newPodIDAttempting", podID,
	)

	// Instead of trying to access the Redis client directly, we'll use debug logs to report what we know
	cm.logger.Debug(ctx, "Lock acquisition failed (SETNX), preparing to publish kill message",
		"sessionKey", sessionKey,
		"newPodIDAttempting", podID,
		"operation", "AcquireSessionLockOrNotify")

	killChannel := rediskeys.SessionKillChannelKey(companyID, agentID, userID)
	killMsg := domain.KillSwitchMessage{NewPodID: podID}

	cm.logger.Debug(ctx, "Preparing to publish session kill message",
		"killChannel", killChannel,
		"message", fmt.Sprintf("%+v", killMsg),
		"sessionKey", sessionKey,
		"operation", "AcquireSessionLockOrNotify")

	if pubErr := cm.killSwitchPublisher.PublishSessionKill(ctx, killChannel, killMsg); pubErr != nil {
		cm.logger.Error(ctx, "Failed to publish session kill message",
			"channel", killChannel,
			"error", pubErr.Error(),
		)
		cm.logger.Debug(ctx, "Session kill message publish failed",
			"killChannel", killChannel,
			"newPodID", podID,
			"error", pubErr.Error(),
			"operation", "AcquireSessionLockOrNotify")
		// Do not immediately fail; proceed to retry lock acquisition as the kill message might still be processed.
	} else {
		cm.logger.Debug(ctx, "Session kill message published successfully",
			"killChannel", killChannel,
			"newPodID", podID,
			"operation", "AcquireSessionLockOrNotify")
	}

	currentDelayMs := initialLockRetryDelayMs
	for i := 0; i < maxSessionLockRetries; i++ {
		select {
		case <-time.After(time.Duration(currentDelayMs) * time.Millisecond):
			cm.logger.Info(ctx, "Retrying AcquireLock (SETNX) for session", "sessionKey", sessionKey, "podID", podID, "attempt", i+1, "delay_ms", currentDelayMs)
			cm.logger.Debug(ctx, "SETNX retry attempt details",
				"sessionKey", sessionKey,
				"podID", podID,
				"attempt", i+1,
				"delay_ms", currentDelayMs,
				"operation", "AcquireSessionLockOrNotify")

			metrics.IncrementSessionLockAttempts("user", "retry_setnx")
			acquired, err = cm.sessionLocker.AcquireLock(ctx, sessionKey, podID, sessionTTL)
			if err != nil {
				cm.logger.Error(ctx, fmt.Sprintf("Failed to retry AcquireLock (SETNX) on attempt %d", i+1), "sessionKey", sessionKey, "error", err.Error())
				cm.logger.Debug(ctx, "SETNX retry attempt failed with error",
					"sessionKey", sessionKey,
					"podID", podID,
					"attempt", i+1,
					"error", err.Error(),
					"operation", "AcquireSessionLockOrNotify")
				// Continue to next retry attempt or force acquire if Redis error occurs
			} else if acquired {
				cm.logger.Info(ctx, fmt.Sprintf("Session lock acquired successfully on SETNX retry attempt %d", i+1), "sessionKey", sessionKey, "podID", podID)
				cm.logger.Debug(ctx, "SETNX retry attempt succeeded",
					"sessionKey", sessionKey,
					"podID", podID,
					"attempt", i+1,
					"operation", "AcquireSessionLockOrNotify")
				metrics.IncrementSessionLockSuccess("user", "retry_setnx")
				return true, nil
			} else {
				cm.logger.Debug(ctx, "SETNX retry attempt failed (lock still held by another pod)",
					"sessionKey", sessionKey,
					"podID", podID,
					"attempt", i+1,
					"operation", "AcquireSessionLockOrNotify")
			}
			// Double the delay for next attempt, up to a maximum
			currentDelayMs *= 2
			if currentDelayMs > maxLockRetryDelayMs {
				currentDelayMs = maxLockRetryDelayMs
			}
		case <-ctx.Done():
			cm.logger.Warn(ctx, "Context cancelled during retry delay for session lock", "sessionKey", sessionKey, "error", ctx.Err())
			cm.logger.Debug(ctx, "Session lock acquisition cancelled due to context",
				"sessionKey", sessionKey,
				"error", ctx.Err(),
				"operation", "AcquireSessionLockOrNotify")
			metrics.IncrementSessionLockFailure("user", "timeout_context_cancelled")
			return false, ctx.Err()
		}
	}

	// All SETNX retries failed, attempt ForceAcquireLock after a final small delay
	cm.logger.Warn(ctx, "All SETNX retries failed. Attempting ForceAcquireLock (SET) for session after final delay.", "sessionKey", sessionKey, "podID", podID)
	cm.logger.Debug(ctx, "Preparing for ForceAcquireLock after all SETNX retries failed",
		"sessionKey", sessionKey,
		"podID", podID,
		"delayMs", lockForceAcquireDelayMs,
		"operation", "AcquireSessionLockOrNotify")

	select {
	case <-time.After(time.Duration(lockForceAcquireDelayMs) * time.Millisecond):
		metrics.IncrementSessionLockAttempts("user", "force_set")
		acquired, err = cm.sessionLocker.ForceAcquireLock(ctx, sessionKey, podID, sessionTTL)
		if err != nil {
			cm.logger.Error(ctx, "Failed to ForceAcquireLock (SET)", "sessionKey", sessionKey, "error", err.Error())
			cm.logger.Debug(ctx, "ForceAcquireLock failed with error",
				"sessionKey", sessionKey,
				"podID", podID,
				"error", err.Error(),
				"operation", "AcquireSessionLockOrNotify")
			metrics.IncrementSessionLockFailure("user", "redis_error_force_set")
			return false, fmt.Errorf("failed to ForceAcquireLock (SET): %w", err)
		}
		if acquired {
			cm.logger.Info(ctx, "Session lock acquired successfully using ForceAcquireLock (SET)", "sessionKey", sessionKey, "podID", podID)
			cm.logger.Debug(ctx, "ForceAcquireLock succeeded",
				"sessionKey", sessionKey,
				"podID", podID,
				"operation", "AcquireSessionLockOrNotify")
			metrics.IncrementSessionLockSuccess("user", "force_set")
			return true, nil
		}
		cm.logger.Debug(ctx, "ForceAcquireLock unexpectedly failed despite using SET",
			"sessionKey", sessionKey,
			"podID", podID,
			"operation", "AcquireSessionLockOrNotify")
	case <-ctx.Done():
		cm.logger.Warn(ctx, "Context cancelled during final delay before ForceAcquireLock", "sessionKey", sessionKey, "error", ctx.Err())
		cm.logger.Debug(ctx, "ForceAcquireLock cancelled due to context",
			"sessionKey", sessionKey,
			"error", ctx.Err(),
			"operation", "AcquireSessionLockOrNotify")
		metrics.IncrementSessionLockFailure("user", "timeout_context_cancelled")
		return false, ctx.Err()
	}

	cm.logger.Error(ctx, "All attempts to acquire session lock failed, including ForceAcquireLock.", "sessionKey", sessionKey)
	cm.logger.Debug(ctx, "Complete failure of all session lock acquisition methods",
		"sessionKey", sessionKey,
		"podID", podID,
		"operation", "AcquireSessionLockOrNotify")
	metrics.IncrementSessionLockFailure("user", "all_attempts_failed")
	return false, fmt.Errorf("all attempts to acquire session lock failed for key %s", sessionKey)
}

// AcquireAdminSessionLockOrNotify attempts to acquire a distributed lock for a new admin session.
// If the lock is already held, it publishes a notification to the admin kill switch channel.
func (cm *ConnectionManager) AcquireAdminSessionLockOrNotify(ctx context.Context, adminID string) (bool, error) {
	cfg := cm.configProvider.Get()
	podID := cfg.Server.PodID
	if podID == "" {
		cm.logger.Error(ctx, "PodID is not configured. Admin session locking will not work correctly.", "operation", "AcquireAdminSessionLockOrNotify")
		metrics.IncrementSessionLockFailure("admin", "config_error_podid")
		return false, fmt.Errorf("podID is not configured")
	}
	adminSessionKey := rediskeys.AdminSessionKey(adminID)
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	cm.logger.Info(ctx, "Attempting to acquire admin session lock",
		"adminSessionKey", adminSessionKey,
		"podID", podID,
		"ttlSeconds", sessionTTL.Seconds(),
	)

	metrics.IncrementSessionLockAttempts("admin", "initial_setnx")
	acquired, err := cm.sessionLocker.AcquireLock(ctx, adminSessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire admin session lock from store (initial attempt)", "error", err.Error(), "adminSessionKey", adminSessionKey)
		metrics.IncrementSessionLockFailure("admin", "redis_error_initial")
		return false, fmt.Errorf("failed to acquire admin session lock: %w", err)
	}

	if acquired {
		cm.logger.Info(ctx, "Admin session lock acquired successfully (initial attempt)", "adminSessionKey", adminSessionKey, "podID", podID)
		metrics.IncrementSessionLockSuccess("admin", "initial_setnx")
		return true, nil
	}

	cm.logger.Warn(ctx, "Failed to acquire admin session lock (already held). Publishing admin kill message and starting retry logic.",
		"adminSessionKey", adminSessionKey,
		"newPodIDAttempting", podID,
	)
	killChannel := rediskeys.AdminSessionKillChannelKey(adminID)
	killMsg := domain.KillSwitchMessage{NewPodID: podID}
	if pubErr := cm.killSwitchPublisher.PublishSessionKill(ctx, killChannel, killMsg); pubErr != nil {
		cm.logger.Error(ctx, "Failed to publish admin session kill message", "channel", killChannel, "error", pubErr.Error())
	}

	currentDelayMs := initialLockRetryDelayMs
	for i := 0; i < maxSessionLockRetries; i++ {
		select {
		case <-time.After(time.Duration(currentDelayMs) * time.Millisecond):
			cm.logger.Info(ctx, "Retrying AcquireLock (SETNX) for admin session", "adminSessionKey", adminSessionKey, "podID", podID, "attempt", i+1, "delay_ms", currentDelayMs)
			metrics.IncrementSessionLockAttempts("admin", "retry_setnx")
			acquired, err = cm.sessionLocker.AcquireLock(ctx, adminSessionKey, podID, sessionTTL)
			if err != nil {
				cm.logger.Error(ctx, fmt.Sprintf("Failed to retry AcquireLock (SETNX) for admin on attempt %d", i+1), "adminSessionKey", adminSessionKey, "error", err.Error())
			} else if acquired {
				cm.logger.Info(ctx, fmt.Sprintf("Admin session lock acquired successfully on SETNX retry attempt %d", i+1), "adminSessionKey", adminSessionKey, "podID", podID)
				metrics.IncrementSessionLockSuccess("admin", "retry_setnx")
				return true, nil
			}
			currentDelayMs *= 2
			if currentDelayMs > maxLockRetryDelayMs {
				currentDelayMs = maxLockRetryDelayMs
			}
		case <-ctx.Done():
			cm.logger.Warn(ctx, "Context cancelled during retry delay for admin session lock", "adminSessionKey", adminSessionKey, "error", ctx.Err())
			metrics.IncrementSessionLockFailure("admin", "timeout_context_cancelled")
			return false, ctx.Err()
		}
	}

	cm.logger.Warn(ctx, "All SETNX retries failed for admin. Attempting ForceAcquireLock (SET) after final delay.", "adminSessionKey", adminSessionKey, "podID", podID)
	select {
	case <-time.After(time.Duration(lockForceAcquireDelayMs) * time.Millisecond):
		metrics.IncrementSessionLockAttempts("admin", "force_set")
		acquired, err = cm.sessionLocker.ForceAcquireLock(ctx, adminSessionKey, podID, sessionTTL)
		if err != nil {
			cm.logger.Error(ctx, "Failed to ForceAcquireLock (SET) for admin session", "adminSessionKey", adminSessionKey, "error", err.Error())
			metrics.IncrementSessionLockFailure("admin", "redis_error_force_set")
			return false, fmt.Errorf("failed to ForceAcquireLock (SET) for admin: %w", err)
		}
		if acquired {
			cm.logger.Info(ctx, "Admin session lock acquired successfully using ForceAcquireLock (SET)", "adminSessionKey", adminSessionKey, "podID", podID)
			metrics.IncrementSessionLockSuccess("admin", "force_set")
			return true, nil
		}
	case <-ctx.Done():
		cm.logger.Warn(ctx, "Context cancelled during final delay before ForceAcquireLock for admin", "adminSessionKey", adminSessionKey, "error", ctx.Err())
		metrics.IncrementSessionLockFailure("admin", "timeout_context_cancelled")
		return false, ctx.Err()
	}

	cm.logger.Error(ctx, "All attempts to acquire admin session lock failed, including ForceAcquireLock.", "adminSessionKey", adminSessionKey)
	metrics.IncrementSessionLockFailure("admin", "all_attempts_failed")
	return false, fmt.Errorf("all attempts to acquire admin session lock failed for key %s", adminSessionKey)
}
