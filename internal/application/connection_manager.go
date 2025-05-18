package application

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket" // For websocket.StatusCode
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)

const sessionKillChannelPrefix = "session_kill:"

// ConnectionManager handles the business logic related to WebSocket connections,
// including session management, authentication, and message routing.
// For now, it will focus on session lock acquisition and local connection management.
type ConnectionManager struct {
	logger               domain.Logger
	configProvider       config.Provider
	sessionLocker        domain.SessionLockManager
	killSwitchPublisher  domain.KillSwitchPublisher
	killSwitchSubscriber domain.KillSwitchSubscriber
	activeConnections    sync.Map // Stores [sessionKey string] -> domain.ManagedConnection

	// For session renewal goroutine
	renewalStopChan chan struct{}
	renewalWg       sync.WaitGroup
}

// NewConnectionManager creates a new instance of ConnectionManager.
func NewConnectionManager(
	logger domain.Logger,
	configProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPublisher domain.KillSwitchPublisher,
	killSwitchSubscriber domain.KillSwitchSubscriber,
) *ConnectionManager {
	return &ConnectionManager{
		logger:               logger,
		configProvider:       configProvider,
		sessionLocker:        sessionLocker,
		killSwitchPublisher:  killSwitchPublisher,
		killSwitchSubscriber: killSwitchSubscriber,
		activeConnections:    sync.Map{},
		renewalStopChan:      make(chan struct{}),
	}
}

// SessionLocker returns the underlying session lock manager.
// This is used by the WebSocket handler to release locks upon connection failure or closure.
func (cm *ConnectionManager) SessionLocker() domain.SessionLockManager {
	return cm.sessionLocker
}

// RegisterConnection stores an active connection associated with a session key.
func (cm *ConnectionManager) RegisterConnection(sessionKey string, conn domain.ManagedConnection) {
	cm.activeConnections.Store(sessionKey, conn)
	cm.logger.Info(conn.Context(), "WebSocket connection registered with ConnectionManager", "sessionKey", sessionKey, "remoteAddr", conn.RemoteAddr())
}

// DeregisterConnection removes an active connection from management and attempts to release its session lock.
func (cm *ConnectionManager) DeregisterConnection(sessionKey string) {
	connVal, loaded := cm.activeConnections.LoadAndDelete(sessionKey)
	logCtx := context.Background() // Base context if connection-specific context is not available

	if loaded {
		if managedConn, ok := connVal.(domain.ManagedConnection); ok {
			logCtx = managedConn.Context() // Use connection's context if available
			cm.logger.Info(logCtx, "WebSocket connection deregistered from ConnectionManager", "sessionKey", sessionKey, "remoteAddr", managedConn.RemoteAddr())
		} else {
			cm.logger.Warn(logCtx, "Deregistered a non-ManagedConnection connection from map", "sessionKey", sessionKey)
		}

		// Attempt to release the session lock associated with this connection
		podID := cm.configProvider.Get().App.PodID
		if podID != "" {
			released, err := cm.sessionLocker.ReleaseLock(logCtx, sessionKey, podID)
			if err != nil {
				cm.logger.Error(logCtx, "Failed to release session lock on deregister", "sessionKey", sessionKey, "podID", podID, "error", err.Error())
			} else if released {
				cm.logger.Info(logCtx, "Successfully released session lock on deregister", "sessionKey", sessionKey, "podID", podID)
			} else {
				cm.logger.Warn(logCtx, "Could not release session lock on deregister (may not exist or not owned by this pod)", "sessionKey", sessionKey, "podID", podID)
			}
		} else {
			cm.logger.Error(logCtx, "PodID is not configured. Cannot release session lock on deregister.", "sessionKey", sessionKey)
		}

	} else {
		cm.logger.Debug(logCtx, "Attempted to deregister a connection not found in map", "sessionKey", sessionKey)
	}
}

// AcquireSessionLockOrNotify attempts to acquire a distributed lock for a new user session.
// If the lock is already held, it publishes a notification to the kill switch channel.
func (cm *ConnectionManager) AcquireSessionLockOrNotify(ctx context.Context, companyID, agentID, userID string) (bool, error) {
	cfg := cm.configProvider.Get()
	podID := cfg.App.PodID
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
	// return false, nil // Original line, will be conditional based on retry

	// Retry logic for Subtask 5.4
	cm.logger.Info(ctx, "Attempting retry for session lock acquisition after kill message", "sessionKey", sessionKey)

	// 1. Wait for a short delay, now configurable
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

	// 2. Retry AcquireLock (SETNX) once more
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

	// 3. If second SETNX also fails, attempt ForceAcquireLock (SET)
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

	// If even ForceAcquireLock somehow fails (e.g. Redis error not caught by the method itself, though it should return true on success)
	cm.logger.Error(ctx, "All attempts to acquire session lock failed, including ForceAcquireLock.", "sessionKey", sessionKey)
	return false, fmt.Errorf("all attempts to acquire session lock failed for key %s", sessionKey)
}

// handleKillSwitchMessage is called when a message is received on a session_kill channel.
func (cm *ConnectionManager) handleKillSwitchMessage(channel string, message domain.KillSwitchMessage) error {
	ctx := context.Background() // Base context for this handler
	cm.logger.Info(ctx, "Received kill switch message via pub/sub",
		"channel", channel,
		"newPodIDInMessage", message.NewPodID,
	)

	currentPodID := cm.configProvider.Get().App.PodID
	if message.NewPodID == currentPodID {
		cm.logger.Info(ctx, "Kill message originated from this pod or is for a session this pod just acquired. No action needed on local connections.",
			"channel", channel,
			"currentPodID", currentPodID,
		)
		return nil
	}

	if !strings.HasPrefix(channel, sessionKillChannelPrefix) {
		cm.logger.Error(ctx, "Received kill switch message on unexpected channel format", "channel", channel)
		return fmt.Errorf("invalid channel format: %s", channel)
	}

	partsStr := strings.TrimPrefix(channel, sessionKillChannelPrefix)
	parts := strings.Split(partsStr, ":")
	if len(parts) != 3 {
		cm.logger.Error(ctx, "Could not parse company/agent/user from kill switch channel", "channel", channel, "parsedParts", partsStr)
		return fmt.Errorf("could not parse identifiers from channel: %s", channel)
	}
	companyID, agentID, userID := parts[0], parts[1], parts[2]
	sessionKey := rediskeys.SessionKey(companyID, agentID, userID)

	cm.logger.Info(ctx, "Processing kill message for potential local connection termination",
		"sessionKey", sessionKey,
		"messageNewPodID", message.NewPodID,
		"currentPodID", currentPodID)

	val, exists := cm.activeConnections.Load(sessionKey)
	if !exists {
		cm.logger.Info(ctx, "No active local connection found for session key, no action needed.", "sessionKey", sessionKey)
		return nil
	}

	managedConn, ok := val.(domain.ManagedConnection)
	if !ok {
		// This should ideally not happen if only ManagedConnection types are stored.
		cm.logger.Error(ctx, "Found non-ManagedConnection type in activeConnections map for session key", "sessionKey", sessionKey)
		// Attempt to remove it anyway to prevent further issues.
		cm.DeregisterConnection(sessionKey)
		return fmt.Errorf("invalid type in activeConnections map for key %s", sessionKey)
	}

	// If we are here, it means: an active local connection for this sessionKey exists,
	// AND the kill message was triggered by a *different* pod (message.NewPodID != currentPodID).
	// This implies our local session is stale and should be terminated.
	logCtx := managedConn.Context() // Use the connection's own context for logging its closure
	cm.logger.Warn(logCtx, "Closing local WebSocket connection due to session conflict (taken over by another pod)",
		"sessionKey", sessionKey,
		"remoteAddr", managedConn.RemoteAddr(),
		"conflictingPodID", message.NewPodID,
	)

	// FR-4: Close with code 4402 "SessionConflict" as per PRD (Section 10.3)
	// Previous code used websocket.StatusPolicyViolation (1008)
	if err := managedConn.Close(websocket.StatusCode(4402), "SessionConflict: Session taken over by another connection"); err != nil {
		cm.logger.Error(logCtx, "Error closing WebSocket connection after session conflict",
			"sessionKey", sessionKey,
			"remoteAddr", managedConn.RemoteAddr(),
			"error", err.Error(),
		)
	}

	cm.DeregisterConnection(sessionKey) // Ensure it's removed from the map
	return nil
}

// StartKillSwitchListener starts the Redis Pub/Sub listener for session kill messages.
func (cm *ConnectionManager) StartKillSwitchListener(ctx context.Context) {
	cm.logger.Info(ctx, "Starting KillSwitch listener...")
	go func() {
		// The sessionKillPattern (e.g. "session_kill:*") is used by the subscriber adapter internally.
		err := cm.killSwitchSubscriber.SubscribeToSessionKillPattern(ctx, rediskeys.SessionKillChannelKey("*", "*", "*"), cm.handleKillSwitchMessage)
		if err != nil {
			cm.logger.Error(ctx, "KillSwitch subscriber failed or terminated", "error", err.Error())
		}
	}()
	cm.logger.Info(ctx, "ConnectionManager KillSwitch listener stopped.")
}

// StopKillSwitchListener gracefully stops the subscriber.
func (cm *ConnectionManager) StopKillSwitchListener() error {
	cm.logger.Info(context.Background(), "Stopping KillSwitch listener...")
	if cm.killSwitchSubscriber != nil {
		return cm.killSwitchSubscriber.Close()
	}
	return nil
}

// StartSessionRenewalLoop starts a goroutine to periodically renew active session locks.
// appCtx is the main application context that can be used to signal shutdown.
func (cm *ConnectionManager) StartSessionRenewalLoop(appCtx context.Context) {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	podID := cfg.App.PodID

	if renewalInterval <= 0 {
		cm.logger.Warn(appCtx, "Session lock renewal interval is not configured or invalid; renewal loop will not start.", "intervalSeconds", cfg.App.TTLRefreshIntervalSeconds)
		return
	}
	if sessionTTL <= 0 {
		cm.logger.Warn(appCtx, "Session lock TTL is not configured or invalid; renewal logic might be ineffective.", "ttlSeconds", cfg.App.SessionTTLSeconds)
		// Allow loop to start, but renewals might fail or be meaningless
	}
	if podID == "" {
		cm.logger.Error(appCtx, "PodID is not configured. Session lock renewal will not work correctly.")
		return
	}

	cm.logger.Info(appCtx, "Starting session renewal loop", "renewalInterval", renewalInterval.String(), "sessionTTL", sessionTTL.String(), "podID", podID)
	cm.renewalWg.Add(1)

	go func() {
		defer cm.renewalWg.Done()
		ticker := time.NewTicker(renewalInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cm.logger.Debug(appCtx, "Session renewal tick: attempting to renew active session locks")
				var keysToRenew []string
				cm.activeConnections.Range(func(key, value interface{}) bool {
					sessionKey, ok := key.(string)
					if ok {
						keysToRenew = append(keysToRenew, sessionKey)
					}
					return true
				})

				if len(keysToRenew) == 0 {
					cm.logger.Debug(appCtx, "No active session locks to renew this tick.")
					continue
				}

				cm.logger.Debug(appCtx, "Found active session locks to renew", "count", len(keysToRenew))

				for _, sessionKey := range keysToRenew {
					// Use a new context for each renewal attempt to avoid carrying over cancellations
					// if one renewal takes too long, though RefreshLock should be quick.
					renewalCtx, cancel := context.WithTimeout(appCtx, 5*time.Second) // Short timeout for Redis op

					refreshed, err := cm.sessionLocker.RefreshLock(renewalCtx, sessionKey, podID, sessionTTL)
					if err != nil {
						cm.logger.Error(renewalCtx, "Error refreshing session lock", "sessionKey", sessionKey, "podID", podID, "error", err.Error())
					} else if refreshed {
						cm.logger.Debug(renewalCtx, "Successfully refreshed session lock", "sessionKey", sessionKey, "podID", podID, "newTTL", sessionTTL.String())
					} else {
						// If not refreshed, it means the lock was not held by this pod or didn't exist.
						// It might have expired or been taken by another pod.
						// No need to explicitly remove from activeConnections here as the normal disconnect flow
						// or Redis TTL expiry should handle it. The connection itself might still be active locally
						// until the next ping/pong failure or a kill message.
						cm.logger.Warn(renewalCtx, "Failed to refresh session lock (not owned or expired)", "sessionKey", sessionKey, "podID", podID)
					}
					cancel()
				}

			case <-cm.renewalStopChan:
				cm.logger.Info(appCtx, "Session renewal loop stopping as requested.")
				return
			case <-appCtx.Done(): // Listen to the application's main context for shutdown
				cm.logger.Info(appCtx, "Session renewal loop stopping due to application context cancellation.")
				return
			}
		}
	}()
}

// StopSessionRenewalLoop signals the session renewal loop to stop and waits for it to complete.
func (cm *ConnectionManager) StopSessionRenewalLoop() {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	if renewalInterval <= 0 || cfg.App.PodID == "" { // Check if loop was started
		cm.logger.Info(context.Background(), "Session renewal loop was not started or podID not set, nothing to stop.")
		return
	}

	cm.logger.Info(context.Background(), "Attempting to stop session renewal loop...")
	close(cm.renewalStopChan)
	cm.renewalWg.Wait()
	cm.logger.Info(context.Background(), "Session renewal loop stopped.")
}

// TODO: Implement other methods for connection lifecycle management as per subsequent subtasks:
// - HandleNewConnection(w http.ResponseWriter, r *http.Request, userCtx *domain.AuthenticatedUserContext)
// - ManageExistingConnection(conn *websocket.ConnectionWrapper, userCtx *domain.AuthenticatedUserContext, companyID, agentID, userID string)
// - RenewAllActiveSessionLocks() // for periodic renewal
