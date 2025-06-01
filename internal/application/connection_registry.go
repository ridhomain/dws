package application

import (
	"context"

	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
)

// RegisterConnection stores the managed connection and registers it with the global consumer
func (cm *ConnectionManager) RegisterConnection(sessionKey string, conn domain.ManagedConnection, companyID, agentID string) {
	// Store in local map (keeping existing functionality)
	cm.activeConnections.Store(sessionKey, conn)
	metrics.IncrementActiveConnections()

	// Register with global consumer for efficient message routing
	if cm.globalConsumer != nil {
		cm.globalConsumer.RegisterConnection(sessionKey, companyID, agentID, conn)
	}

	cm.logger.Info(conn.Context(), "WebSocket connection registered",
		"sessionKey", sessionKey,
		"companyID", companyID,
		"agentID", agentID,
		"remoteAddr", conn.RemoteAddr())

	// Log global consumer stats
	if cm.globalConsumer != nil {
		stats := cm.globalConsumer.GetStats()
		cm.logger.Debug(conn.Context(), "Global consumer stats after registration",
			"total_connections", stats["total_connections"],
			"company_count", stats["company_count"])
	}
}

// DeregisterConnection removes a connection from management and global consumer
func (cm *ConnectionManager) DeregisterConnection(sessionKey string) {
	connVal, loaded := cm.activeConnections.LoadAndDelete(sessionKey)
	logCtx := context.Background()

	if loaded {
		metrics.DecrementActiveConnections()
		if managedConn, ok := connVal.(domain.ManagedConnection); ok {
			logCtx = managedConn.Context()
			cm.logger.Info(logCtx, "WebSocket connection deregistered",
				"sessionKey", sessionKey,
				"remoteAddr", managedConn.RemoteAddr())
		}

		// Deregister from global consumer
		if cm.globalConsumer != nil {
			cm.globalConsumer.DeregisterConnection(sessionKey)
		}

		// Release session lock (existing logic)
		podID := cm.configProvider.Get().Server.PodID
		if podID != "" {
			releaseCtx := context.Background()
			if reqID, ok := logCtx.Value(contextkeys.RequestIDKey).(string); ok && reqID != "" {
				releaseCtx = context.WithValue(releaseCtx, contextkeys.RequestIDKey, reqID)
			}

			released, err := cm.sessionLocker.ReleaseLock(releaseCtx, sessionKey, podID)
			if err != nil {
				cm.logger.Error(logCtx, "Failed to release session lock on deregister",
					"sessionKey", sessionKey, "podID", podID, "error", err.Error())
			} else if released {
				cm.logger.Info(logCtx, "Successfully released session lock on deregister",
					"sessionKey", sessionKey, "podID", podID)
			}
		}
	}

	// Log global consumer stats
	if cm.globalConsumer != nil {
		stats := cm.globalConsumer.GetStats()
		cm.logger.Debug(logCtx, "Global consumer stats after deregistration",
			"total_connections", stats["total_connections"],
			"company_count", stats["company_count"])
	}
}

// GracefullyCloseAllConnections updated to work with global consumer
func (cm *ConnectionManager) GracefullyCloseAllConnections(closeCode websocket.StatusCode, reason string) {
	cm.logger.Info(context.Background(), "Initiating graceful closure of all active WebSocket connections...",
		"code", closeCode, "reason", reason)

	closedCount := 0
	errResp := domain.NewErrorResponse(domain.ErrInternal, "Service shutting down", "The WebSocket service is being gracefully terminated.")

	// Close regular connections
	cm.activeConnections.Range(func(key, value interface{}) bool {
		sessionKey, okSessionKey := key.(string)
		conn, okConn := value.(domain.ManagedConnection)
		if !okSessionKey || !okConn {
			cm.logger.Error(context.Background(), "Invalid type in activeConnections map during graceful shutdown")
			return true
		}

		cm.logger.Info(conn.Context(), "Sending close frame to WebSocket connection",
			"sessionKey", sessionKey, "remoteAddr", conn.RemoteAddr(), "code", closeCode)

		if err := conn.CloseWithError(errResp, reason); err != nil {
			cm.logger.Warn(conn.Context(), "Error sending close frame during graceful shutdown",
				"sessionKey", sessionKey, "error", err.Error())
		}
		closedCount++
		return true
	})

	// Close admin connections
	cm.activeAdminConnections.Range(func(key, value interface{}) bool {
		adminSessionKey, okSessionKey := key.(string)
		conn, okConn := value.(domain.ManagedConnection)
		if !okSessionKey || !okConn {
			cm.logger.Error(context.Background(), "Invalid type in activeAdminConnections map during graceful shutdown")
			return true
		}

		cm.logger.Info(conn.Context(), "Sending close frame to admin WebSocket connection",
			"adminSessionKey", adminSessionKey, "remoteAddr", conn.RemoteAddr(), "code", closeCode)

		if err := conn.CloseWithError(errResp, reason); err != nil {
			cm.logger.Warn(conn.Context(), "Error sending close frame to admin connection during graceful shutdown",
				"adminSessionKey", adminSessionKey, "error", err.Error())
		}
		closedCount++
		return true
	})

	cm.logger.Info(context.Background(), "Graceful close frames sent to active connections", "count", closedCount)
}
