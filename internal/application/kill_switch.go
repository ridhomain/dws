package application

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)

const (
	sessionKillChannelPrefix      = "session_kill:"       // For user sessions: session_kill:<company>:<agent>:<user>
	adminSessionKillChannelPrefix = "session_kill:admin:" // New prefix for admin kill messages: session_kill:admin:<adminID>
)

// handleKillSwitchMessage is called when a message is received on a session_kill channel for regular users.
func (cm *ConnectionManager) handleKillSwitchMessage(channel string, message domain.KillSwitchMessage) error {
	ctx := context.Background()
	cm.logger.Info(ctx, "Received user kill switch message via pub/sub",
		"channel", channel,
		"newPodIDInMessage", message.NewPodID,
	)

	cm.logger.Debug(ctx, "Processing received user kill switch message",
		"channel", channel,
		"new_pod_id", message.NewPodID,
		"operation", "handleKillSwitchMessage")

	currentPodID := cm.configProvider.Get().Server.PodID
	if message.NewPodID == currentPodID {
		cm.logger.Info(ctx, "User kill message originated from this pod or is for a session this pod just acquired. No action needed.", "channel", channel, "currentPodID", currentPodID)
		cm.logger.Debug(ctx, "Ignoring kill message originating from this pod",
			"channel", channel,
			"new_pod_id", message.NewPodID,
			"current_pod_id", currentPodID,
			"operation", "handleKillSwitchMessage")
		return nil
	}

	if !strings.HasPrefix(channel, sessionKillChannelPrefix) || strings.HasPrefix(channel, adminSessionKillChannelPrefix) {
		cm.logger.Error(ctx, "handleKillSwitchMessage received message on unexpected channel format or admin channel", "channel", channel)
		cm.logger.Debug(ctx, "Invalid channel format for user kill message",
			"channel", channel,
			"session_prefix", sessionKillChannelPrefix,
			"admin_prefix", adminSessionKillChannelPrefix,
			"operation", "handleKillSwitchMessage")
		return fmt.Errorf("invalid user channel format for handleKillSwitchMessage: %s", channel)
	}

	partsStr := strings.TrimPrefix(channel, sessionKillChannelPrefix)
	parts := strings.Split(partsStr, ":")

	cm.logger.Debug(ctx, "Parsed channel parts from kill message",
		"channel", channel,
		"parts_string", partsStr,
		"parts_count", len(parts),
		"parts", parts,
		"operation", "handleKillSwitchMessage")

	if len(parts) != 3 {
		cm.logger.Error(ctx, "Could not parse company/agent/user from user kill switch channel", "channel", channel, "parsedParts", partsStr)
		cm.logger.Debug(ctx, "Invalid number of parts in channel format",
			"channel", channel,
			"parts_string", partsStr,
			"parts_count", len(parts),
			"expected_parts", 3,
			"operation", "handleKillSwitchMessage")
		return fmt.Errorf("could not parse identifiers from user channel: %s", channel)
	}

	companyID, agentID, userID := parts[0], parts[1], parts[2]
	sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
	cm.logger.Info(ctx, "Processing user kill message for potential local connection termination",
		"sessionKey", sessionKey,
		"messageNewPodID", message.NewPodID,
		"currentPodID", currentPodID)

	cm.logger.Debug(ctx, "Looking up active connection for kill message",
		"session_key", sessionKey,
		"company_id", companyID,
		"agent_id", agentID,
		"user_id", userID,
		"new_pod_id", message.NewPodID,
		"operation", "handleKillSwitchMessage")

	val, exists := cm.activeConnections.Load(sessionKey)
	if !exists {
		cm.logger.Info(ctx, "No active local user connection found for session key, no action needed.", "sessionKey", sessionKey)
		cm.logger.Debug(ctx, "No connection found to terminate for kill message",
			"session_key", sessionKey,
			"new_pod_id", message.NewPodID,
			"operation", "handleKillSwitchMessage")
		return nil
	}

	cm.logger.Debug(ctx, "Found active connection matching kill message",
		"session_key", sessionKey,
		"new_pod_id", message.NewPodID,
		"operation", "handleKillSwitchMessage")

	managedConn, ok := val.(domain.ManagedConnection)
	if !ok {
		cm.logger.Error(ctx, "Found non-ManagedConnection type in activeConnections map for user session key", "sessionKey", sessionKey)
		cm.logger.Debug(ctx, "Type mismatch for connection in activeConnections map",
			"session_key", sessionKey,
			"value_type", fmt.Sprintf("%T", val),
			"expected_type", "domain.ManagedConnection",
			"operation", "handleKillSwitchMessage")
		cm.DeregisterConnection(sessionKey)
		return fmt.Errorf("invalid type in activeConnections map for user key %s", sessionKey)
	}

	logCtx := managedConn.Context()
	cm.logger.Warn(logCtx, "Closing local user WebSocket connection due to session conflict (taken over by another pod)",
		"sessionKey", sessionKey,
		"remoteAddr", managedConn.RemoteAddr(),
		"conflictingPodID", message.NewPodID,
	)

	cm.logger.Debug(logCtx, "Preparing to close connection for kill message",
		"session_key", sessionKey,
		"remote_addr", managedConn.RemoteAddr(),
		"new_pod_id", message.NewPodID,
		"operation", "handleKillSwitchMessage")

	errResp := domain.NewErrorResponse(domain.ErrSessionConflict, "Session conflict", "Session taken over by another connection")
	if err := managedConn.CloseWithError(errResp, "SessionConflict: Session taken over by another connection"); err != nil {
		cm.logger.Error(logCtx, "Error closing user WebSocket connection after session conflict",
			"sessionKey", sessionKey,
			"remoteAddr", managedConn.RemoteAddr(),
			"error", err.Error(),
		)
		cm.logger.Debug(logCtx, "Failed to close connection with error message",
			"session_key", sessionKey,
			"remote_addr", managedConn.RemoteAddr(),
			"error", err.Error(),
			"operation", "handleKillSwitchMessage")
	} else {
		cm.logger.Debug(logCtx, "Successfully closed connection with session conflict error",
			"session_key", sessionKey,
			"remote_addr", managedConn.RemoteAddr(),
			"operation", "handleKillSwitchMessage")
	}

	cm.logger.Debug(logCtx, "Deregistering connection after kill message processing",
		"session_key", sessionKey,
		"operation", "handleKillSwitchMessage")
	cm.DeregisterConnection(sessionKey)
	return nil
}

// handleAdminKillSwitchMessage is called when a message is received on an admin_session_kill channel.
func (cm *ConnectionManager) handleAdminKillSwitchMessage(channel string, message domain.KillSwitchMessage) error {
	ctx := context.Background()
	cm.logger.Info(ctx, "Received admin kill switch message via pub/sub",
		"channel", channel,
		"newPodIDInMessage", message.NewPodID,
	)

	cm.logger.Debug(ctx, "Processing received admin kill switch message",
		"channel", channel,
		"new_pod_id", message.NewPodID,
		"operation", "handleAdminKillSwitchMessage")

	currentPodID := cm.configProvider.Get().Server.PodID
	if message.NewPodID == currentPodID {
		cm.logger.Info(ctx, "Admin kill message originated from this pod or is for a session this pod just acquired. No action needed.", "channel", channel, "currentPodID", currentPodID)
		cm.logger.Debug(ctx, "Ignoring admin kill message originating from this pod",
			"channel", channel,
			"new_pod_id", message.NewPodID,
			"current_pod_id", currentPodID,
			"operation", "handleAdminKillSwitchMessage")
		return nil
	}

	if !strings.HasPrefix(channel, adminSessionKillChannelPrefix) {
		cm.logger.Error(ctx, "handleAdminKillSwitchMessage received message on unexpected channel format", "channel", channel)
		cm.logger.Debug(ctx, "Invalid channel format for admin kill message",
			"channel", channel,
			"expected_prefix", adminSessionKillChannelPrefix,
			"operation", "handleAdminKillSwitchMessage")
		return fmt.Errorf("invalid admin channel format for handleAdminKillSwitchMessage: %s", channel)
	}

	adminID := strings.TrimPrefix(channel, adminSessionKillChannelPrefix)
	adminSessionKey := rediskeys.AdminSessionKey(adminID)

	cm.logger.Info(ctx, "Processing admin kill message for potential local admin connection termination",
		"adminSessionKey", adminSessionKey,
		"messageNewPodID", message.NewPodID,
		"currentPodID", currentPodID)

	cm.logger.Debug(ctx, "Looking up active admin connection for kill message",
		"admin_session_key", adminSessionKey,
		"admin_id", adminID,
		"new_pod_id", message.NewPodID,
		"operation", "handleAdminKillSwitchMessage")

	val, exists := cm.activeConnections.Load(adminSessionKey)
	if !exists {
		cm.logger.Info(ctx, "No active local admin connection found for session key, no action needed.", "adminSessionKey", adminSessionKey)
		cm.logger.Debug(ctx, "No admin connection found to terminate for kill message",
			"admin_session_key", adminSessionKey,
			"admin_id", adminID,
			"new_pod_id", message.NewPodID,
			"operation", "handleAdminKillSwitchMessage")
		return nil
	}

	cm.logger.Debug(ctx, "Found active admin connection matching kill message",
		"admin_session_key", adminSessionKey,
		"admin_id", adminID,
		"new_pod_id", message.NewPodID,
		"operation", "handleAdminKillSwitchMessage")

	managedConn, ok := val.(domain.ManagedConnection)
	if !ok {
		cm.logger.Error(ctx, "Found non-ManagedConnection type in activeConnections map for admin session key", "adminSessionKey", adminSessionKey)
		cm.logger.Debug(ctx, "Type mismatch for admin connection in activeConnections map",
			"admin_session_key", adminSessionKey,
			"value_type", fmt.Sprintf("%T", val),
			"expected_type", "domain.ManagedConnection",
			"operation", "handleAdminKillSwitchMessage")
		cm.DeregisterConnection(adminSessionKey)
		return fmt.Errorf("invalid type in activeConnections map for admin key %s", adminSessionKey)
	}

	logCtx := managedConn.Context()
	cm.logger.Warn(logCtx, "Closing local admin WebSocket connection due to session conflict (taken over by another pod)",
		"adminSessionKey", adminSessionKey,
		"remoteAddr", managedConn.RemoteAddr(),
		"conflictingPodID", message.NewPodID,
	)

	cm.logger.Debug(logCtx, "Preparing to close admin connection for kill message",
		"admin_session_key", adminSessionKey,
		"remote_addr", managedConn.RemoteAddr(),
		"new_pod_id", message.NewPodID,
		"operation", "handleAdminKillSwitchMessage")

	errResp := domain.NewErrorResponse(domain.ErrSessionConflict, "Session conflict", "Admin session taken over by another connection")
	if err := managedConn.CloseWithError(errResp, "AdminSessionConflict: Session taken over by another connection"); err != nil {
		cm.logger.Error(logCtx, "Error closing admin WebSocket connection after session conflict",
			"adminSessionKey", adminSessionKey,
			"remoteAddr", managedConn.RemoteAddr(),
			"error", err.Error(),
		)
		cm.logger.Debug(logCtx, "Failed to close admin connection with error message",
			"admin_session_key", adminSessionKey,
			"remote_addr", managedConn.RemoteAddr(),
			"error", err.Error(),
			"operation", "handleAdminKillSwitchMessage")
	} else {
		cm.logger.Debug(logCtx, "Successfully closed admin connection with session conflict error",
			"admin_session_key", adminSessionKey,
			"remote_addr", managedConn.RemoteAddr(),
			"operation", "handleAdminKillSwitchMessage")
	}

	cm.logger.Debug(logCtx, "Deregistering admin connection after kill message processing",
		"admin_session_key", adminSessionKey,
		"operation", "handleAdminKillSwitchMessage")
	cm.DeregisterConnection(adminSessionKey)
	return nil
}

// StartKillSwitchListener starts the Redis Pub/Sub listener for session kill messages for regular users.
func (cm *ConnectionManager) StartKillSwitchListener(ctx context.Context) {
	cm.logger.Info(ctx, "Starting User KillSwitch listener...")
	safego.Execute(ctx, cm.logger, "UserKillSwitchSubscriberLoop", func() {
		pattern := rediskeys.SessionKillChannelKey("*", "*", "*") // e.g., session_kill:*:*:*
		cm.logger.Info(ctx, "User KillSwitch listener subscribing to pattern", "pattern", pattern)
		err := cm.killSwitchSubscriber.SubscribeToSessionKillPattern(ctx, pattern, cm.handleKillSwitchMessage)
		if err != nil {
			if ctx.Err() == context.Canceled {
				cm.logger.Info(ctx, "User KillSwitch subscriber stopped due to context cancellation.")
			} else {
				cm.logger.Error(ctx, "User KillSwitch subscriber failed or terminated", "error", err.Error())
			}
		}
		cm.logger.Info(ctx, "ConnectionManager User KillSwitch listener goroutine finished.")
	})
}

// StartAdminKillSwitchListener starts the Redis Pub/Sub listener for admin session kill messages.
func (cm *ConnectionManager) StartAdminKillSwitchListener(ctx context.Context) {
	cm.logger.Info(ctx, "Starting Admin KillSwitch listener...")
	safego.Execute(ctx, cm.logger, "AdminKillSwitchSubscriberLoop", func() {
		pattern := rediskeys.AdminSessionKillChannelKey("*") // e.g., session_kill:admin:*
		cm.logger.Info(ctx, "Admin KillSwitch listener subscribing to pattern", "pattern", pattern)
		err := cm.killSwitchSubscriber.SubscribeToSessionKillPattern(ctx, pattern, cm.handleAdminKillSwitchMessage)
		if err != nil {
			if ctx.Err() == context.Canceled {
				cm.logger.Info(ctx, "Admin KillSwitch subscriber stopped due to context cancellation.")
			} else {
				cm.logger.Error(ctx, "Admin KillSwitch subscriber failed or terminated", "error", err.Error())
			}
		}
		cm.logger.Info(ctx, "ConnectionManager Admin KillSwitch listener goroutine finished.")
	})
}

// StopKillSwitchListener gracefully stops all subscriptions made by the KillSwitchSubscriber.
// This assumes the underlying KillSwitchSubscriber.Close() handles all its active subscriptions.
func (cm *ConnectionManager) StopKillSwitchListener() error {
	cm.logger.Info(context.Background(), "Stopping all KillSwitch listeners (via shared subscriber Close)... ")
	if cm.killSwitchSubscriber != nil {
		return cm.killSwitchSubscriber.Close()
	}
	return nil
}

// StopAdminKillSwitchListener is now effectively a no-op because StopKillSwitchListener stops the shared subscriber.
// Kept for conceptual separation but points to the shared nature of the Close().
func (cm *ConnectionManager) StopAdminKillSwitchListener() error {
	cm.logger.Info(context.Background(), "Stopping Admin KillSwitch listener called - this is a no-op as StopKillSwitchListener closes the shared subscriber.")
	return nil // No separate action if subscriber is shared and closed by the other Stop method.
}
