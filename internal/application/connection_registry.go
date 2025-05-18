package application

import (
	"context"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

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
