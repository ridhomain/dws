package application

import (
	"context"
	"fmt"
	"strings"

	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)

const sessionKillChannelPrefix = "session_kill:"

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
		cm.logger.Error(ctx, "Found non-ManagedConnection type in activeConnections map for session key", "sessionKey", sessionKey)
		cm.DeregisterConnection(sessionKey)
		return fmt.Errorf("invalid type in activeConnections map for key %s", sessionKey)
	}

	logCtx := managedConn.Context()
	cm.logger.Warn(logCtx, "Closing local WebSocket connection due to session conflict (taken over by another pod)",
		"sessionKey", sessionKey,
		"remoteAddr", managedConn.RemoteAddr(),
		"conflictingPodID", message.NewPodID,
	)

	if err := managedConn.Close(websocket.StatusCode(4402), "SessionConflict: Session taken over by another connection"); err != nil {
		cm.logger.Error(logCtx, "Error closing WebSocket connection after session conflict",
			"sessionKey", sessionKey,
			"remoteAddr", managedConn.RemoteAddr(),
			"error", err.Error(),
		)
	}

	cm.DeregisterConnection(sessionKey)
	return nil
}

// StartKillSwitchListener starts the Redis Pub/Sub listener for session kill messages.
func (cm *ConnectionManager) StartKillSwitchListener(ctx context.Context) {
	cm.logger.Info(ctx, "Starting KillSwitch listener...")
	go func() {
		err := cm.killSwitchSubscriber.SubscribeToSessionKillPattern(ctx, rediskeys.SessionKillChannelKey("*", "*", "*"), cm.handleKillSwitchMessage)
		if err != nil {
			cm.logger.Error(ctx, "KillSwitch subscriber failed or terminated", "error", err.Error())
		}
	}()
	cm.logger.Info(ctx, "ConnectionManager KillSwitch listener stopped.") // This log might be misleading as it logs before the goroutine actually stops.
}

// StopKillSwitchListener gracefully stops the subscriber.
func (cm *ConnectionManager) StopKillSwitchListener() error {
	cm.logger.Info(context.Background(), "Stopping KillSwitch listener...")
	if cm.killSwitchSubscriber != nil {
		return cm.killSwitchSubscriber.Close()
	}
	return nil
}
