package application

import (
	"context"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// RegisterConnection stores the managed connection and registers its initial chat route.
func (cm *ConnectionManager) RegisterConnection(sessionKey string, conn domain.ManagedConnection, companyID, agentID string) {
	cm.activeConnections.Store(sessionKey, conn)
	metrics.IncrementActiveConnections()
	cm.logger.Info(conn.Context(), "WebSocket connection registered with ConnectionManager", "sessionKey", sessionKey, "remoteAddr", conn.RemoteAddr())

	// Register initial chat route for this connection
	cfg := cm.configProvider.Get()
	podID := cfg.Server.PodID
	routeTTL := time.Duration(cfg.App.RouteTTLSeconds) * time.Second
	if routeTTL <= 0 {
		routeTTL = 30 * time.Second // Default if not configured
		cm.logger.Warn(conn.Context(), "RouteTTLSeconds not configured or zero, using default 30s for chat route registration", "sessionKey", sessionKey)
	}

	if podID == "" {
		cm.logger.Error(conn.Context(), "PodID is not configured. Cannot register chat route.", "sessionKey", sessionKey)
		return
	}

	if cm.routeRegistry != nil {
		err := cm.routeRegistry.RegisterChatRoute(conn.Context(), companyID, agentID, podID, routeTTL)
		if err != nil {
			cm.logger.Error(conn.Context(), "Failed to register chat route on connection registration",
				"sessionKey", sessionKey, "companyID", companyID, "agentID", agentID, "podID", podID, "error", err.Error(),
			)
		} else {
			cm.logger.Info(conn.Context(), "Successfully registered chat route on connection registration",
				"sessionKey", sessionKey, "companyID", companyID, "agentID", agentID, "podID", podID, "ttl", routeTTL.String(),
			)
		}
	} else {
		cm.logger.Error(conn.Context(), "RouteRegistry is nil in ConnectionManager. Cannot register chat route.", "sessionKey", sessionKey)
	}
}

// DeregisterConnection removes an active connection from management and attempts to release its session lock.
func (cm *ConnectionManager) DeregisterConnection(sessionKey string) {
	connVal, loaded := cm.activeConnections.LoadAndDelete(sessionKey)
	logCtx := context.Background() // Base context if connection-specific context is not available

	if loaded {
		metrics.DecrementActiveConnections()
		if managedConn, ok := connVal.(domain.ManagedConnection); ok {
			logCtx = managedConn.Context() // Use connection's context if available
			cm.logger.Info(logCtx, "WebSocket connection deregistered from ConnectionManager", "sessionKey", sessionKey, "remoteAddr", managedConn.RemoteAddr())
		} else {
			cm.logger.Warn(logCtx, "Deregistered a non-ManagedConnection connection from map", "sessionKey", sessionKey)
		}

		// Attempt to release the session lock associated with this connection
		podID := cm.configProvider.Get().Server.PodID
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
