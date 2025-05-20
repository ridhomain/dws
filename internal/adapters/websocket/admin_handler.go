package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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

	wsConnLifetimeCtx, cancelWsConnLifetimeCtx := context.WithCancel(r.Context())
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

	h.connManager.RegisterConnection(adminSessionKey, wrappedConn, "", "") // Pass empty strings for company/agent for admin conns

	defer func() {
		h.logger.Info(wrappedConn.Context(), "Admin connection management goroutine finished. Deregistering admin connection.", "admin_session_key", adminSessionKey)
		duration := time.Since(startTime).Seconds()
		metrics.ObserveConnectionDuration(duration)         // Observe for admin connections
		h.connManager.DeregisterConnection(adminSessionKey) // Uses generic deregister for now
		// Release lock on clean disconnect
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer releaseCancel()
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, adminSessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(wrappedConn.Context(), "Failed to release admin session lock on connection close", "admin_session_key", adminSessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(wrappedConn.Context(), "Successfully released admin session lock on connection close", "admin_session_key", adminSessionKey)
			} else {
				h.logger.Warn(wrappedConn.Context(), "Failed to release admin session lock on connection close (not held or value mismatch)", "admin_session_key", adminSessionKey)
			}
		}
	}()

	safego.Execute(wsConnLifetimeCtx, h.logger, fmt.Sprintf("AdminWebSocketConnectionManager-%s", adminSessionKey), func() {
		h.manageAdminConnection(wsConnLifetimeCtx, wrappedConn, adminCtx)
	})
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

			var eventPayload domain.EnrichedEventPayload
			if err := json.Unmarshal(msg.Data, &eventPayload); err != nil {
				h.logger.Error(msgCtx, "Admin NATS: Failed to unmarshal agent event payload", "subject", msg.Subject, "error", err.Error(), "admin_id", adminInfo.AdminID)
				_ = msg.Ack()
				return
			}

			wsMessage := domain.NewEventMessage(eventPayload)
			if err := conn.WriteJSON(wsMessage); err != nil {
				h.logger.Error(msgCtx, "Admin NATS: Failed to forward agent event to WebSocket", "subject", msg.Subject, "error", err.Error(), "admin_id", adminInfo.AdminID)
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeEvent)
			}
			_ = msg.Ack()
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

	if pingInterval > 0 {
		pinger := time.NewTicker(pingInterval)
		defer pinger.Stop()
		safego.Execute(connCtx, conn.logger, fmt.Sprintf("AdminWebSocketPinger-%s", conn.RemoteAddr()), func() {
			for {
				select {
				case <-pinger.C:
					pingWriteCtx, pingCancel := context.WithTimeout(connCtx, writeTimeout)
					if err := conn.Ping(pingWriteCtx); err != nil {
						h.logger.Error(connCtx, "Failed to send admin ping", "error", err.Error(), "admin_id", adminInfo.AdminID)
						pingCancel()
						errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to send ping", err.Error())
						conn.CloseWithError(errResp, "Admin Ping failure")
						return
					}
					pingCancel()
					h.logger.Debug(connCtx, "Sent ping to admin client", "admin_id", adminInfo.AdminID)
					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Admin Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr(), "admin_id", adminInfo.AdminID)
						errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No pong responses received within the configured duration.")
						conn.CloseWithError(errResp, "Admin Pong timeout")
						return
					}
				case <-connCtx.Done():
					h.logger.Info(connCtx, "Admin connection context done in pinger, stopping pinger.", "admin_id", adminInfo.AdminID)
					return
				}
			}
		})
	}

	// Read loop
	for {
		var readCtx context.Context
		var cancelRead context.CancelFunc
		if pongWaitDuration > 0 {
			readCtx, cancelRead = context.WithTimeout(connCtx, pongWaitDuration)
		} else {
			readCtx = connCtx
		}

		msgType, p, errRead := conn.ReadMessage(readCtx)
		if cancelRead != nil {
			cancelRead()
		}

		if errRead != nil {
			if errors.Is(readCtx.Err(), context.DeadlineExceeded) {
				h.logger.Warn(connCtx, "Admin Pong timeout: No message received. Closing connection.", "admin_id", adminInfo.AdminID)
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No message received within configured timeout period.")
				conn.CloseWithError(errResp, "Admin Pong timeout")
				return
			}
			closeStatus := websocket.CloseStatus(errRead)
			if closeStatus == websocket.StatusNormalClosure || closeStatus == websocket.StatusGoingAway {
				h.logger.Info(connCtx, "Admin WebSocket connection closed by peer", "status_code", closeStatus, "admin_id", adminInfo.AdminID)
			} else if errors.Is(errRead, context.Canceled) || connCtx.Err() == context.Canceled {
				h.logger.Info(connCtx, "Admin WebSocket connection context canceled.", "admin_id", adminInfo.AdminID)
			} else if closeStatus == -1 && (strings.Contains(strings.ToLower(errRead.Error()), "eof") || strings.Contains(strings.ToLower(errRead.Error()), "closed")) {
				h.logger.Info(connCtx, "Admin WebSocket read EOF or closed. Peer disconnected.", "admin_id", adminInfo.AdminID, "error", errRead.Error())
			} else {
				h.logger.Error(connCtx, "Error reading from admin WebSocket", "error", errRead.Error(), "admin_id", adminInfo.AdminID)
			}
			return
		}

		h.logger.Debug(connCtx, "Received message from admin WebSocket", "type", msgType.String(), "payload_len", len(p), "admin_id", adminInfo.AdminID)
		// Admin interface might not expect many client-sent messages other than control messages (if any defined later).
		// For now, increment a generic received metric if it's a text message.
		if msgType == websocket.MessageText {
			metrics.IncrementMessagesReceived("admin_text_message") // Generic type for admin messages
			// Optionally unmarshal if there's a defined admin protocol, otherwise just log receipt for now.
			h.logger.Info(connCtx, "Admin client sent a text message.", "payload", string(p))
		} else if msgType == websocket.MessageBinary {
			metrics.IncrementMessagesReceived("admin_binary_message")
		}
	}
}
