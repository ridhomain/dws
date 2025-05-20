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
	currentPodID := cm.configProvider.Get().Server.PodID
	if message.NewPodID == currentPodID {
		cm.logger.Info(ctx, "User kill message originated from this pod or is for a session this pod just acquired. No action needed.", "channel", channel, "currentPodID", currentPodID)
		return nil
	}

	if !strings.HasPrefix(channel, sessionKillChannelPrefix) || strings.HasPrefix(channel, adminSessionKillChannelPrefix) {
		cm.logger.Error(ctx, "handleKillSwitchMessage received message on unexpected channel format or admin channel", "channel", channel)
		return fmt.Errorf("invalid user channel format for handleKillSwitchMessage: %s", channel)
	}
	partsStr := strings.TrimPrefix(channel, sessionKillChannelPrefix)
	parts := strings.Split(partsStr, ":")
	if len(parts) != 3 {
		cm.logger.Error(ctx, "Could not parse company/agent/user from user kill switch channel", "channel", channel, "parsedParts", partsStr)
		return fmt.Errorf("could not parse identifiers from user channel: %s", channel)
	}

	companyID, agentID, userID := parts[0], parts[1], parts[2]
	sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
	cm.logger.Info(ctx, "Processing user kill message for potential local connection termination",
		"sessionKey", sessionKey,
		"messageNewPodID", message.NewPodID,
		"currentPodID", currentPodID)
	val, exists := cm.activeConnections.Load(sessionKey)
	if !exists {
		cm.logger.Info(ctx, "No active local user connection found for session key, no action needed.", "sessionKey", sessionKey)
		return nil
	}
	managedConn, ok := val.(domain.ManagedConnection)
	if !ok {
		cm.logger.Error(ctx, "Found non-ManagedConnection type in activeConnections map for user session key", "sessionKey", sessionKey)
		cm.DeregisterConnection(sessionKey)
		return fmt.Errorf("invalid type in activeConnections map for user key %s", sessionKey)
	}
	logCtx := managedConn.Context()
	cm.logger.Warn(logCtx, "Closing local user WebSocket connection due to session conflict (taken over by another pod)",
		"sessionKey", sessionKey,
		"remoteAddr", managedConn.RemoteAddr(),
		"conflictingPodID", message.NewPodID,
	)
	errResp := domain.NewErrorResponse(domain.ErrSessionConflict, "Session conflict", "Session taken over by another connection")
	if err := managedConn.CloseWithError(errResp, "SessionConflict: Session taken over by another connection"); err != nil {
		cm.logger.Error(logCtx, "Error closing user WebSocket connection after session conflict",
			"sessionKey", sessionKey,
			"remoteAddr", managedConn.RemoteAddr(),
			"error", err.Error(),
		)
	}
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
	currentPodID := cm.configProvider.Get().Server.PodID
	if message.NewPodID == currentPodID {
		cm.logger.Info(ctx, "Admin kill message originated from this pod or is for a session this pod just acquired. No action needed.", "channel", channel, "currentPodID", currentPodID)
		return nil
	}

	if !strings.HasPrefix(channel, adminSessionKillChannelPrefix) {
		cm.logger.Error(ctx, "handleAdminKillSwitchMessage received message on unexpected channel format", "channel", channel)
		return fmt.Errorf("invalid admin channel format for handleAdminKillSwitchMessage: %s", channel)
	}
	adminID := strings.TrimPrefix(channel, adminSessionKillChannelPrefix)
	adminSessionKey := rediskeys.AdminSessionKey(adminID)

	cm.logger.Info(ctx, "Processing admin kill message for potential local admin connection termination",
		"adminSessionKey", adminSessionKey,
		"messageNewPodID", message.NewPodID,
		"currentPodID", currentPodID)

	val, exists := cm.activeConnections.Load(adminSessionKey)
	if !exists {
		cm.logger.Info(ctx, "No active local admin connection found for session key, no action needed.", "adminSessionKey", adminSessionKey)
		return nil
	}

	managedConn, ok := val.(domain.ManagedConnection)
	if !ok {
		cm.logger.Error(ctx, "Found non-ManagedConnection type in activeConnections map for admin session key", "adminSessionKey", adminSessionKey)
		cm.DeregisterConnection(adminSessionKey)
		return fmt.Errorf("invalid type in activeConnections map for admin key %s", adminSessionKey)
	}

	logCtx := managedConn.Context()
	cm.logger.Warn(logCtx, "Closing local admin WebSocket connection due to session conflict (taken over by another pod)",
		"adminSessionKey", adminSessionKey,
		"remoteAddr", managedConn.RemoteAddr(),
		"conflictingPodID", message.NewPodID,
	)
	errResp := domain.NewErrorResponse(domain.ErrSessionConflict, "Session conflict", "Admin session taken over by another connection")
	if err := managedConn.CloseWithError(errResp, "AdminSessionConflict: Session taken over by another connection"); err != nil {
		cm.logger.Error(logCtx, "Error closing admin WebSocket connection after session conflict",
			"adminSessionKey", adminSessionKey,
			"remoteAddr", managedConn.RemoteAddr(),
			"error", err.Error(),
		)
	}
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
