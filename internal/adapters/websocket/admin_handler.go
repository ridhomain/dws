package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"runtime/debug"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)

// AdminHandler handles WebSocket connections for the /ws/admin endpoint.
// This is a placeholder and will be expanded in Subtask 12.2 and 12.3.
type AdminHandler struct {
	logger         domain.Logger
	configProvider config.Provider
	connManager    *application.ConnectionManager
	natsAdapter    domain.NatsConsumer
	// Add other dependencies like NATS adapter, connection manager for admin sessions later.
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter domain.NatsConsumer) *AdminHandler {
	return &AdminHandler{
		logger:         logger,
		configProvider: cfgProvider,
		connManager:    connManager,
		natsAdapter:    natsAdapter,
	}
}

// ServeHTTP is the entry point for admin WebSocket upgrade requests.
// It expects to be called after APIKeyAuthMiddleware and AdminAuthMiddleware.
func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	adminCtx, ok := r.Context().Value(contextkeys.AdminUserContextKey).(*domain.AdminUserContext)
	if !ok || adminCtx == nil {
		h.logger.Error(r.Context(), "AdminUserContext not found after middleware chain for /ws/admin")
		domain.NewErrorResponse(domain.ErrInternal, "Authentication context missing", "Server configuration error.").WriteJSON(w, http.StatusInternalServerError)
		return
	}

	h.logger.Info(r.Context(), "/ws/admin endpoint hit by admin", "admin_id", adminCtx.AdminID)

	// Session Lock Acquisition for Admin (Part of FR-ADMIN-3 / Subtask 12.4)
	// This is a simplified version for now; full retry and notification logic will be in ConnectionManager for 12.4
	adminSessionKey := rediskeys.AdminSessionKey(adminCtx.AdminID)
	currentPodID := h.configProvider.Get().Server.PodID
	// sessionTTL := time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second // TTL managed by AcquireAdminSessionLockOrNotify

	// Use the ConnectionManager method for robust lock acquisition
	lockAcqCtx, lockAcqCancel := context.WithTimeout(r.Context(), 10*time.Second) // Longer timeout for full process with retries
	defer lockAcqCancel()
	acquired, err := h.connManager.AcquireAdminSessionLockOrNotify(lockAcqCtx, adminCtx.AdminID)
	if err != nil {
		h.logger.Error(r.Context(), "Failed during admin session lock acquisition attempt via ConnectionManager", "error", err, "admin_id", adminCtx.AdminID)
		domain.NewErrorResponse(domain.ErrInternal, "Failed to process admin session.", err.Error()).WriteJSON(w, http.StatusInternalServerError)
		return
	}
	if !acquired {
		h.logger.Warn(r.Context(), "Admin session lock not acquired (conflict)", "admin_id", adminCtx.AdminID)
		metrics.IncrementSessionConflicts("admin") // Admin session conflict
		domain.NewErrorResponse(domain.ErrSessionConflict, "Admin session already active elsewhere.", "").WriteJSON(w, http.StatusConflict)
		return
	}
	h.logger.Info(r.Context(), "Admin session lock successfully acquired", "admin_session_key", adminSessionKey)

	// Create a new context for this specific WebSocket connection's lifecycle.
	// This context should be independent of the HTTP request's lifecycle once the connection is established.
	baseCtxForWs := context.Background()
	// Propagate essential values from the request context, like request_id.
	if reqID, ok := r.Context().Value(contextkeys.RequestIDKey).(string); ok && reqID != "" {
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.RequestIDKey, reqID)
		h.logger.Debug(r.Context(), "Propagated request_id to admin WebSocket lifetime context", "request_id", reqID)
	} else {
		// If no request ID in r.Context(), generate a new one for the WebSocket connection itself
		newReqID := uuid.NewString()
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.RequestIDKey, newReqID)
		h.logger.Debug(r.Context(), "No request_id in r.Context(), generated new request_id for admin WebSocket lifetime context", "new_request_id", newReqID)
	}

	// Propagate admin context for operations throughout the connection's lifetime
	if adminCtx != nil {
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.AdminUserContextKey, adminCtx)
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.UserIDKey, adminCtx.AdminID) // Admin ID as user ID for consistency
		h.logger.Debug(r.Context(), "Propagated AdminUserContext to WebSocket lifetime context", "admin_id", adminCtx.AdminID)
	}

	wsConnLifetimeCtx, cancelWsConnLifetimeCtx := context.WithCancel(baseCtxForWs)
	var wrappedConn *Connection
	startTime := time.Now() // For connection duration metric

	opts := websocket.AcceptOptions{
		Subprotocols: []string{"json.v1"},
		OnPongReceived: func(ctx context.Context, pongPayload []byte) {
			if wrappedConn != nil {
				h.logger.Debug(wrappedConn.Context(), "Admin Pong received")
				wrappedConn.UpdateLastPongTime()
			}
		},
	}

	c, err := websocket.Accept(w, r, &opts)
	if err != nil {
		h.logger.Error(r.Context(), "Admin WebSocket upgrade failed", "error", err, "admin_id", adminCtx.AdminID)
		// Release lock if upgrade fails
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer releaseCancel()
			// This should use the actual podID that acquired the lock
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, adminSessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(r.Context(), "Failed to release admin session lock after upgrade failure", "sessionKey", adminSessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(r.Context(), "Successfully released admin session lock after upgrade failure", "sessionKey", adminSessionKey)
			}
		}
		cancelWsConnLifetimeCtx()
		return
	}

	metrics.IncrementConnectionsTotal() // Increment for admin connections too

	wrappedConn = NewConnection(wsConnLifetimeCtx, cancelWsConnLifetimeCtx, c, r.RemoteAddr, h.logger, h.configProvider, adminSessionKey)
	h.logger.Info(wrappedConn.Context(), "Admin WebSocket connection established",
		"remoteAddr", wrappedConn.RemoteAddr(),
		"subprotocol", c.Subprotocol(),
		"admin_id", adminCtx.AdminID,
		"admin_session_key", adminSessionKey,
	)

	h.connManager.RegisterConnection(adminSessionKey, wrappedConn, "", "")

	// Record initial activity for the admin session
	if h.connManager.SessionLocker() != nil {
		adaptiveSessionCfg := h.configProvider.Get().AdaptiveTTL.SessionLock
		activityTTL := time.Duration(adaptiveSessionCfg.MaxTTLSeconds) * time.Second
		if activityTTL <= 0 {
			activityTTL = time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second * 2
		}
		if errAct := h.connManager.SessionLocker().RecordActivity(wrappedConn.Context(), adminSessionKey, activityTTL); errAct != nil {
			h.logger.Error(wrappedConn.Context(), "Failed to record initial admin session activity", "adminSessionKey", adminSessionKey, "error", errAct)
		} else {
			h.logger.Debug(wrappedConn.Context(), "Recorded initial admin session activity", "adminSessionKey", adminSessionKey, "activityTTL", activityTTL.String())
		}
	}

	// It will execute when the manageAdminConnection function finishes.
	defer func() {
		h.logger.Info(wrappedConn.Context(), "Admin connection management lifecycle ending. Deregistering admin connection.", "admin_session_key", adminSessionKey)
		duration := time.Since(startTime).Seconds()
		metrics.ObserveConnectionDuration(duration)         // Observe for admin connections
		h.connManager.DeregisterConnection(adminSessionKey) // Uses generic deregister for now
		cancelWsConnLifetimeCtx()                           // Ensure context is cancelled as ServeHTTP exits.
		// Do not attempt to release the lock here - the ConnectionManager.DeregisterConnection already does this
	}()

	// Call manageAdminConnection directly with panic recovery.
	// Panic recovery is integrated here, similar to what safego.Execute provided.
	defer func() {
		if r := recover(); r != nil {
			logCtx := wsConnLifetimeCtx
			if wsConnLifetimeCtx.Err() != nil {
				logCtx = context.Background()
			}
			h.logger.Error(logCtx, fmt.Sprintf("Panic recovered in AdminWebSocketConnectionManager-%s", adminSessionKey),
				"panic_info", fmt.Sprintf("%v", r),
				"stacktrace", string(debug.Stack()),
			)
			// Ensure connection is closed and deregistered on panic within manageAdminConnection
			// wrappedConn.Close() might be redundant if panic was due to conn error, but good for safety.
			// Deregistration is handled by the outer defer.
		}
	}()

	// When manageAdminConnection returns, the defers in ServeHTTP will be triggered.
	h.manageAdminConnection(wsConnLifetimeCtx, wrappedConn, adminCtx)
}

// manageAdminConnection handles the lifecycle of a single admin WebSocket connection.
func (h *AdminHandler) manageAdminConnection(connCtx context.Context, conn *Connection, adminInfo *domain.AdminUserContext) {
	// For normal/graceful closure, we intentionally use a direct Close instead of CloseWithError
	// since this is an expected termination (e.g., function exit), not an error condition that needs to be reported to the client.
	defer conn.Close(websocket.StatusNormalClosure, "admin connection ended") // Ensures WebSocket closes if all other error handling is bypassed

	h.logger.Info(connCtx, "Admin WebSocket connection management started",
		"admin_id", adminInfo.AdminID,
		"remote_addr", conn.RemoteAddr(),
	)

	// Send "ready" message
	readyMessage := domain.NewReadyMessage()
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to admin client", "error", err.Error(), "admin_id", adminInfo.AdminID)
		return
	}
	metrics.IncrementMessagesSent(domain.MessageTypeReady) // Sent to admin
	h.logger.Info(connCtx, "Sent 'ready' message to admin client", "admin_id", adminInfo.AdminID)

	var natsSubscription domain.NatsMessageSubscription
	if h.natsAdapter != nil {
		companyPattern := adminInfo.SubscribedCompanyID
		agentPattern := adminInfo.SubscribedAgentID

		if companyPattern == "" {
			companyPattern = "*"
		} // Default to wildcard if not specified
		if agentPattern == "" {
			agentPattern = "*"
		} // Default to wildcard if not specified

		natsMsgHandler := func(msg *nats.Msg) {
			metrics.IncrementNatsMessagesReceived(msg.Subject) // Increment NATS received metric for admin

			// Start: request_id handling for NATS message
			natsRequestID := msg.Header.Get(middleware.XRequestIDHeader)
			if natsRequestID == "" {
				natsRequestID = uuid.NewString()
				h.logger.Debug(connCtx, "Generated new request_id for Admin NATS message", "subject", msg.Subject, "new_request_id", natsRequestID, "admin_id", adminInfo.AdminID)
			} else {
				h.logger.Debug(connCtx, "Using existing request_id from Admin NATS message header", "subject", msg.Subject, "request_id", natsRequestID, "admin_id", adminInfo.AdminID)
			}
			msgCtx := context.WithValue(connCtx, contextkeys.RequestIDKey, natsRequestID)
			// End: request_id handling for NATS message

			h.logger.Info(msgCtx, "Admin NATS: Received message on agent events subject",
				"subject", msg.Subject, "data_len", len(msg.Data), "admin_id", adminInfo.AdminID,
			)

			h.logger.Debug(msgCtx, "Processing admin NATS message",
				"subject", msg.Subject,
				"data_size", len(msg.Data),
				"admin_id", adminInfo.AdminID,
				"operation", "AdminNatsMessageHandler")

			var eventPayload domain.EnrichedEventPayload
			if err := json.Unmarshal(msg.Data, &eventPayload); err != nil {
				h.logger.Error(msgCtx, "Admin NATS: Failed to unmarshal agent event payload", "subject", msg.Subject, "error", err.Error(), "admin_id", adminInfo.AdminID)
				_ = msg.Ack()
				return
			}

			wsMessage := domain.NewEventMessage(eventPayload)
			if err := conn.WriteJSON(wsMessage); err != nil {
				h.logger.Error(msgCtx, "Admin NATS: Failed to forward agent event to WebSocket", "subject", msg.Subject, "error", err.Error(), "admin_id", adminInfo.AdminID)
				// Don't ACK the message if WebSocket write failed - this allows for redelivery
				return
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeEvent)
				h.logger.Debug(msgCtx, "Successfully delivered admin NATS message to WebSocket",
					"subject", msg.Subject,
					"event_id", eventPayload.EventID,
					"admin_id", adminInfo.AdminID,
					"operation", "AdminNatsMessageHandler")
			}

			// Only ACK the message after successful WebSocket delivery
			if ackErr := msg.Ack(); ackErr != nil {
				h.logger.Error(msgCtx, "Failed to ACK admin NATS message",
					"subject", msg.Subject,
					"error", ackErr.Error(),
					"admin_id", adminInfo.AdminID)
			} else {
				h.logger.Debug(msgCtx, "Successfully ACKed admin NATS message",
					"subject", msg.Subject,
					"event_id", eventPayload.EventID,
					"admin_id", adminInfo.AdminID,
					"operation", "AdminNatsMessageHandler")
			}
		}

		var subErr error
		natsSubscription, subErr = h.natsAdapter.SubscribeToAgentEvents(connCtx, companyPattern, agentPattern, natsMsgHandler)
		if subErr != nil {
			h.logger.Error(connCtx, "Failed to subscribe to NATS agent events for admin",
				"companyPattern", companyPattern, "agentPattern", agentPattern, "error", subErr.Error(), "admin_id", adminInfo.AdminID,
			)
			// Optionally send error to client and close
			errorMsg := domain.NewErrorResponse(domain.ErrSubscriptionFailure, "Could not subscribe to agent events", subErr.Error())
			if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorMsg)); sendErr != nil {
				h.logger.Error(connCtx, "Failed to send NATS subscription error to admin client", "error", sendErr.Error())
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeError) // Error sent to admin
			}
			// conn.Close(websocket.StatusInternalError, "NATS subscription failure")
			// return // For now, let it run without NATS if sub fails, but log error.
		} else {
			h.logger.Info(connCtx, "Successfully subscribed to NATS agent events for admin",
				"companyPattern", companyPattern, "agentPattern", agentPattern, "subject", natsSubscription.Subject, "admin_id", adminInfo.AdminID,
			)
			defer func() {
				if natsSubscription != nil {
					h.logger.Info(connCtx, "Unsubscribing from NATS agent events for admin", "subject", natsSubscription.Subject, "admin_id", adminInfo.AdminID)
					if unsubErr := natsSubscription.Drain(); unsubErr != nil {
						h.logger.Error(connCtx, "Error draining NATS admin subscription", "subject", natsSubscription.Subject, "error", unsubErr.Error())
					}
				}
			}()
		}
	} else {
		h.logger.Warn(connCtx, "NATS adapter not available for admin handler, cannot subscribe to agent events.", "admin_id", adminInfo.AdminID)
	}

	// Ping/Pong and Read Loop (similar to user's manageConnection)
	appCfg := conn.config
	pingInterval := time.Duration(appCfg.PingIntervalSeconds) * time.Second
	pongWaitDuration := time.Duration(appCfg.PongWaitSeconds) * time.Second
	writeTimeout := time.Duration(appCfg.WriteTimeoutSeconds) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}

	h.logger.Info(connCtx, "Admin connection configuration",
		"admin_id", adminInfo.AdminID,
		"ping_interval", pingInterval.String(),
		"pong_wait_duration", pongWaitDuration.String(),
		"write_timeout", writeTimeout.String(),
		"context_deadline", func() string {
			if deadline, ok := connCtx.Deadline(); ok {
				return deadline.String()
			}
			return "no deadline"
		}())

	if pingInterval > 0 {
		// Pinger goroutine
		safego.Execute(connCtx, h.logger, fmt.Sprintf("AdminPinger-%s", conn.RemoteAddr()), func() {
			ticker := time.NewTicker(pingInterval)
			defer ticker.Stop()

			for {
				select {
				case <-connCtx.Done():
					h.logger.Info(connCtx, "Admin connection context done in pinger, stopping pinger.", "admin_id", adminInfo.AdminID)
					return
				case <-ticker.C:
					writeCtx, cancel := context.WithTimeout(connCtx, writeTimeout)
					if err := conn.Ping(writeCtx); err != nil {
						h.logger.Error(writeCtx, "Admin ping failed", "error", err.Error(), "admin_id", adminInfo.AdminID)
						cancel()
						return
					}
					cancel()
					h.logger.Debug(connCtx, "Admin ping sent successfully", "admin_id", adminInfo.AdminID)
				}
			}
		})
	}

	// Read loop
	for {
		var readCtx context.Context
		var cancelRead context.CancelFunc

		// For admin connections, don't use pong timeout for read operations
		// since admin clients primarily receive messages and may not send any data
		// The pong timeout is already handled in the pinger goroutine above
		readCtx = connCtx

		msgType, p, errRead := conn.ReadMessage(readCtx)
		if cancelRead != nil {
			cancelRead()
		}

		if errRead != nil {
			// Check if error is due to context cancellation (graceful shutdown)
			if errors.Is(errRead, context.Canceled) || connCtx.Err() == context.Canceled {
				h.logger.Info(connCtx, "Admin connection read loop exiting due to context cancellation (graceful shutdown)", "admin_id", adminInfo.AdminID)
				return
			}

			// Check if error is due to context deadline exceeded
			if errors.Is(errRead, context.DeadlineExceeded) || connCtx.Err() == context.DeadlineExceeded {
				h.logger.Info(connCtx, "Admin connection read loop exiting due to context deadline exceeded", "admin_id", adminInfo.AdminID)
				return
			}

			// Handle WebSocket specific close statuses
			closeStatus := websocket.CloseStatus(errRead)
			if closeStatus == websocket.StatusNormalClosure || closeStatus == websocket.StatusGoingAway {
				h.logger.Info(connCtx, "Admin connection closed normally by client", "admin_id", adminInfo.AdminID, "status", closeStatus.String())
			} else if closeStatus == websocket.StatusNoStatusRcvd {
				h.logger.Info(connCtx, "Admin connection closed without status (likely network issue)", "admin_id", adminInfo.AdminID, "error", errRead.Error())
			} else {
				// Check if the error message contains context-related errors that might not be caught by errors.Is
				errMsg := strings.ToLower(errRead.Error())
				if strings.Contains(errMsg, "context canceled") || strings.Contains(errMsg, "context cancelled") {
					h.logger.Info(connCtx, "Admin connection read error due to context cancellation (graceful shutdown)", "admin_id", adminInfo.AdminID, "error", errRead.Error())
				} else {
					h.logger.Error(connCtx, "Admin connection read error", "error", errRead.Error(), "admin_id", adminInfo.AdminID, "close_status", closeStatus.String())
				}
			}
			return
		}

		if msgType == websocket.MessageText {
			h.logger.Debug(connCtx, "Admin received text message", "admin_id", adminInfo.AdminID, "message_size", len(p))
			// Handle admin-specific messages here if needed
			// For now, just log and continue
		} else {
			h.logger.Debug(connCtx, "Admin received non-text message", "admin_id", adminInfo.AdminID, "message_type", msgType.String(), "message_size", len(p))
		}
	}
}
