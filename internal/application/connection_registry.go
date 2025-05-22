package application

import (
	"context"
	"fmt"
	"time"

	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
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
			// Create a new detached context for ReleaseLock operation to prevent context cancellation issues
			// This ensures that ReleaseLock can still complete even if the connection context was cancelled
			releaseCtx := context.Background()

			// Inherit request_id from the original context if possible
			if reqID, ok := logCtx.Value(contextkeys.RequestIDKey).(string); ok && reqID != "" {
				releaseCtx = context.WithValue(releaseCtx, contextkeys.RequestIDKey, reqID)
			}

			released, err := cm.sessionLocker.ReleaseLock(releaseCtx, sessionKey, podID)
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

// GracefullyCloseAllConnections sends a graceful close frame to all active WebSocket connections.
// This is typically called during a controlled service shutdown.
func (cm *ConnectionManager) GracefullyCloseAllConnections(closeCode websocket.StatusCode, reason string) {
	cm.logger.Info(context.Background(), "Initiating graceful closure of all active WebSocket connections...", "code", closeCode, "reason", reason)
	closedCount := 0

	// Create a standard error response for graceful shutdown
	errResp := domain.NewErrorResponse(domain.ErrInternal, "Service shutting down", "The WebSocket service is being gracefully terminated.")

	cm.activeConnections.Range(func(key, value interface{}) bool {
		sessionKey, okSessionKey := key.(string)
		conn, okConn := value.(domain.ManagedConnection)
		if !okSessionKey || !okConn {
			cm.logger.Error(context.Background(), "Invalid type in activeConnections map during graceful shutdown", "key_type", fmt.Sprintf("%T", key), "value_type", fmt.Sprintf("%T", value))
			return true // Continue to next item
		}

		cm.logger.Info(conn.Context(), "Sending close frame to WebSocket connection", "sessionKey", sessionKey, "remoteAddr", conn.RemoteAddr(), "code", closeCode)
		if err := conn.CloseWithError(errResp, reason); err != nil {
			// Log error, but underlying connection context cancellation should ensure cleanup via DeregisterConnection later if not already.
			cm.logger.Warn(conn.Context(), "Error sending close frame during graceful shutdown (will be forcibly closed)", "sessionKey", sessionKey, "error", err.Error())
		}
		closedCount++
		return true // Continue to next item
	})

	// Also close any admin connections
	cm.activeAdminConnections.Range(func(key, value interface{}) bool {
		adminSessionKey, okSessionKey := key.(string)
		conn, okConn := value.(domain.ManagedConnection)
		if !okSessionKey || !okConn {
			cm.logger.Error(context.Background(), "Invalid type in activeAdminConnections map during graceful shutdown", "key_type", fmt.Sprintf("%T", key), "value_type", fmt.Sprintf("%T", value))
			return true // Continue to next item
		}

		cm.logger.Info(conn.Context(), "Sending close frame to admin WebSocket connection", "adminSessionKey", adminSessionKey, "remoteAddr", conn.RemoteAddr(), "code", closeCode)
		if err := conn.CloseWithError(errResp, reason); err != nil {
			cm.logger.Warn(conn.Context(), "Error sending close frame to admin connection during graceful shutdown (will be forcibly closed)", "adminSessionKey", adminSessionKey, "error", err.Error())
		}
		closedCount++
		return true // Continue to next item
	})

	cm.logger.Info(context.Background(), "Graceful close frames sent to active connections", "count", closedCount)
	// The actual deregistration and lock release happens when each connection's manageConnection goroutine exits due to context cancellation from conn.Close().
}
