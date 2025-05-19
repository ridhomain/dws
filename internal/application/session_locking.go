package application

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
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

	acquired, err := cm.sessionLocker.AcquireLock(ctx, sessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire session lock from store",
			"error", err.Error(),
			"sessionKey", sessionKey,
		)
		return false, fmt.Errorf("failed to acquire session lock: %w", err)
	}

	if acquired {
		cm.logger.Info(ctx, "Session lock acquired successfully",
			"sessionKey", sessionKey,
			"podID", podID,
		)
		return true, nil
	}

	cm.logger.Warn(ctx, "Failed to acquire session lock (already held). Publishing kill message.",
		"sessionKey", sessionKey,
		"newPodIDAttempting", podID,
	)
	killChannel := rediskeys.SessionKillChannelKey(companyID, agentID, userID)
	killMsg := domain.KillSwitchMessage{NewPodID: podID}

	if pubErr := cm.killSwitchPublisher.PublishSessionKill(ctx, killChannel, killMsg); pubErr != nil {
		cm.logger.Error(ctx, "Failed to publish session kill message",
			"channel", killChannel,
			"error", pubErr.Error(),
		)
	}

	cm.logger.Info(ctx, "Attempting retry for session lock acquisition after kill message", "sessionKey", sessionKey)

	retryDelayMs := cfg.App.SessionLockRetryDelayMs
	if retryDelayMs <= 0 {
		retryDelayMs = 250 // Default to 250ms if not configured or invalid
		cm.logger.Warn(ctx, "SessionLockRetryDelayMs not configured or invalid, defaulting", "default_ms", retryDelayMs, "sessionKey", sessionKey)
	}
	retryDelayDuration := time.Duration(retryDelayMs) * time.Millisecond

	select {
	case <-time.After(retryDelayDuration):
		cm.logger.Debug(ctx, "Retry delay completed", "sessionKey", sessionKey, "delay", retryDelayDuration)
	case <-ctx.Done():
		cm.logger.Warn(ctx, "Context cancelled during retry delay for session lock", "sessionKey", sessionKey, "error", ctx.Err())
		return false, ctx.Err() // Propagate context cancellation
	}

	cm.logger.Info(ctx, "Retrying AcquireLock (SETNX) for session", "sessionKey", sessionKey, "podID", podID)
	acquired, err = cm.sessionLocker.AcquireLock(ctx, sessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to retry AcquireLock (SETNX)", "sessionKey", sessionKey, "error", err.Error())
		return false, fmt.Errorf("failed to retry AcquireLock (SETNX): %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Session lock acquired successfully on SETNX retry", "sessionKey", sessionKey, "podID", podID)
		return true, nil
	}

	cm.logger.Warn(ctx, "SETNX retry failed. Attempting ForceAcquireLock (SET) for session.", "sessionKey", sessionKey, "podID", podID)
	acquired, err = cm.sessionLocker.ForceAcquireLock(ctx, sessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to ForceAcquireLock (SET)", "sessionKey", sessionKey, "error", err.Error())
		return false, fmt.Errorf("failed to ForceAcquireLock (SET): %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Session lock acquired successfully using ForceAcquireLock (SET)", "sessionKey", sessionKey, "podID", podID)
		return true, nil
	}

	cm.logger.Error(ctx, "All attempts to acquire session lock failed, including ForceAcquireLock.", "sessionKey", sessionKey)
	return false, fmt.Errorf("all attempts to acquire session lock failed for key %s", sessionKey)
}

// AcquireAdminSessionLockOrNotify attempts to acquire a distributed lock for a new admin session.
// If the lock is already held, it publishes a notification to the admin kill switch channel.
func (cm *ConnectionManager) AcquireAdminSessionLockOrNotify(ctx context.Context, adminID string) (bool, error) {
	cfg := cm.configProvider.Get()
	podID := cfg.Server.PodID
	if podID == "" {
		cm.logger.Error(ctx, "PodID is not configured. Admin session locking will not work correctly.", "operation", "AcquireAdminSessionLockOrNotify")
		return false, fmt.Errorf("podID is not configured")
	}

	adminSessionKey := rediskeys.AdminSessionKey(adminID)
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second // Reuse same session TTL config for now

	cm.logger.Info(ctx, "Attempting to acquire admin session lock",
		"adminSessionKey", adminSessionKey,
		"podID", podID,
		"ttlSeconds", sessionTTL.Seconds(),
	)

	acquired, err := cm.sessionLocker.AcquireLock(ctx, adminSessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire admin session lock from store", "error", err.Error(), "adminSessionKey", adminSessionKey)
		return false, fmt.Errorf("failed to acquire admin session lock: %w", err)
	}

	if acquired {
		cm.logger.Info(ctx, "Admin session lock acquired successfully", "adminSessionKey", adminSessionKey, "podID", podID)
		return true, nil
	}

	cm.logger.Warn(ctx, "Failed to acquire admin session lock (already held). Publishing admin kill message.",
		"adminSessionKey", adminSessionKey,
		"newPodIDAttempting", podID,
	)

	killChannel := rediskeys.AdminSessionKillChannelKey(adminID)
	killMsg := domain.KillSwitchMessage{NewPodID: podID} // Same message structure
	if pubErr := cm.killSwitchPublisher.PublishSessionKill(ctx, killChannel, killMsg); pubErr != nil {
		cm.logger.Error(ctx, "Failed to publish admin session kill message", "channel", killChannel, "error", pubErr.Error())
		// Non-fatal for the current attempt, but log it.
	}

	cm.logger.Info(ctx, "Attempting retry for admin session lock acquisition after kill message", "adminSessionKey", adminSessionKey)
	retryDelayMs := cfg.App.SessionLockRetryDelayMs
	if retryDelayMs <= 0 {
		retryDelayMs = 250 // Default
		cm.logger.Warn(ctx, "SessionLockRetryDelayMs not configured or invalid for admin, defaulting", "default_ms", retryDelayMs, "adminSessionKey", adminSessionKey)
	}
	retryDelayDuration := time.Duration(retryDelayMs) * time.Millisecond

	select {
	case <-time.After(retryDelayDuration):
		cm.logger.Debug(ctx, "Admin retry delay completed", "adminSessionKey", adminSessionKey, "delay", retryDelayDuration)
	case <-ctx.Done():
		cm.logger.Warn(ctx, "Context cancelled during retry delay for admin session lock", "adminSessionKey", adminSessionKey, "error", ctx.Err())
		return false, ctx.Err()
	}

	cm.logger.Info(ctx, "Retrying AcquireLock (SETNX) for admin session", "adminSessionKey", adminSessionKey, "podID", podID)
	acquired, err = cm.sessionLocker.AcquireLock(ctx, adminSessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to retry AcquireLock (SETNX) for admin session", "adminSessionKey", adminSessionKey, "error", err.Error())
		return false, fmt.Errorf("failed to retry AcquireLock (SETNX) for admin: %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Admin session lock acquired successfully on SETNX retry", "adminSessionKey", adminSessionKey, "podID", podID)
		return true, nil
	}

	cm.logger.Warn(ctx, "Admin SETNX retry failed. Attempting ForceAcquireLock (SET) for admin session.", "adminSessionKey", adminSessionKey, "podID", podID)
	acquired, err = cm.sessionLocker.ForceAcquireLock(ctx, adminSessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to ForceAcquireLock (SET) for admin session", "adminSessionKey", adminSessionKey, "error", err.Error())
		return false, fmt.Errorf("failed to ForceAcquireLock (SET) for admin: %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Admin session lock acquired successfully using ForceAcquireLock (SET)", "adminSessionKey", adminSessionKey, "podID", podID)
		return true, nil
	}

	cm.logger.Error(ctx, "All attempts to acquire admin session lock failed, including ForceAcquireLock.", "adminSessionKey", adminSessionKey)
	return false, fmt.Errorf("all attempts to acquire admin session lock failed for key %s", adminSessionKey)
}
