package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	// "time" // Not strictly needed for basic upgrade, can be added for timeouts later

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"

	"github.com/coder/websocket"
)

// Handler handles WebSocket connection upgrades and subsequent communication.
type Handler struct {
	logger         domain.Logger
	configProvider config.Provider
	connManager    *application.ConnectionManager
	// Future dependencies: connectionManager domain.ConnectionManager
}

// NewHandler creates a new WebSocket Handler.
func NewHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager) *Handler {
	return &Handler{
		logger:         logger,
		configProvider: cfgProvider,
		connManager:    connManager,
	}
}

// ServeHTTP is the entry point for WebSocket upgrade requests.
// It expects to be called after authentication middleware (APIKeyAuth, CompanyTokenAuth).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	company := r.PathValue("company")
	agent := r.PathValue("agent")
	user := r.URL.Query().Get("user")
	token := r.URL.Query().Get("token") // Token is for CompanyTokenAuth, but good to log its presence

	if company == "" || agent == "" {
		h.logger.Warn(r.Context(), "WebSocket upgrade failed: Missing company or agent in path",
			"remote_addr", r.RemoteAddr, "path", r.URL.Path, "company", company, "agent", agent, "user", user, "token_present", token != "",
		)
		domain.NewErrorResponse(domain.ErrBadRequest, "Missing company or agent in path parameters.", "").WriteJSON(w, http.StatusBadRequest)
		return
	}

	// TODO: Later, the AuthenticatedUserContext from CompanyTokenAuthMiddleware should be retrieved here.
	// For now, we're just upgrading with APIKeyAuth having passed.

	// Create a new context for this specific WebSocket connection's lifecycle.
	// This context will be passed to the Connection wrapper.
	// It's derived from r.Context() initially to carry over request-scoped values like request_id.
	// However, its lifecycle is independent of the HTTP request once the connection is established.
	wsConnLifetimeCtx, cancelWsConnLifetimeCtx := context.WithCancel(r.Context())

	// Session Lock Acquisition (FR-4 part 1)
	// This context should be short-lived for the lock acquisition attempt.
	lockAcqCtx, lockAcqCancel := context.WithTimeout(r.Context(), 5*time.Second) // Example timeout
	defer lockAcqCancel()

	acquired, err := h.connManager.AcquireSessionLockOrNotify(lockAcqCtx, company, agent, user)
	if err != nil {
		h.logger.Error(r.Context(), "Failed during session lock acquisition attempt", "error", err, "company", company, "agent", agent, "user", user)
		domain.NewErrorResponse(domain.ErrInternal, "Failed to process session.", err.Error()).WriteJSON(w, http.StatusInternalServerError)
		cancelWsConnLifetimeCtx() // Important: cancel the context we created if we're aborting
		return
	}
	if !acquired {
		h.logger.Warn(r.Context(), "Session lock not acquired (conflict or notification sent)", "company", company, "agent", agent, "user", user)
		// Send a specific WebSocket close code if we could upgrade, or HTTP error if pre-upgrade.
		// For now, sending HTTP 409 Conflict as an example. The PRD implies the kill happens on the *other* client.
		// This new connection should be denied.
		domain.NewErrorResponse(domain.ErrSessionConflict, "Session already active elsewhere.", "").WriteJSON(w, http.StatusConflict)
		cancelWsConnLifetimeCtx() // Important: cancel before returning
		return
	}

	// If lock acquired, proceed to upgrade.
	sessionKey := rediskeys.SessionKey(company, agent, user)
	h.logger.Info(r.Context(), "Session lock successfully acquired, proceeding to WebSocket upgrade", "sessionKey", sessionKey)

	var wrappedConn *Connection // Declare wrappedConn here to be accessible for OnPongReceived

	opts := websocket.AcceptOptions{
		Subprotocols: []string{"json.v1"},
		// TODO (FR-9B): Add Compression options if defined in config
		// TODO (FR-9B): Consider InsecureSkipVerify for local dev if using self-signed certs, controlled by config.
		OnPongReceived: func(ctx context.Context, pongPayload []byte) {
			if wrappedConn != nil {
				h.logger.Debug(wrappedConn.Context(), "Pong received via AcceptOptions callback")
				wrappedConn.UpdateLastPongTime()
			}
		},
	}

	c, err := websocket.Accept(w, r, &opts)
	if err != nil {
		h.logger.Error(r.Context(), "WebSocket upgrade failed", "error", err, "company", company, "agent", agent, "user", user)
		// No HTTP response can be written here as hijack already happened or failed.
		// Release the lock as we failed to establish the connection for this sessionKey
		// This requires the current PodID which should be available in config.
		currentPodID := h.configProvider.Get().App.PodID
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer releaseCancel()
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, sessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(r.Context(), "Failed to release session lock after upgrade failure", "sessionKey", sessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(r.Context(), "Successfully released session lock after upgrade failure", "sessionKey", sessionKey)
			}
		}
		cancelWsConnLifetimeCtx() // Important: cancel before returning
		return
	}

	// Assign to wrappedConn *after* successful upgrade and *before* manageConnection so callback can use it.
	wrappedConn = NewConnection(wsConnLifetimeCtx, cancelWsConnLifetimeCtx, c, r.RemoteAddr, h.logger, h.configProvider)

	h.logger.Info(wrappedConn.Context(), "WebSocket connection established",
		"remoteAddr", wrappedConn.RemoteAddr(),
		"subprotocol", c.Subprotocol(),
		"company", company, "agent", agent, "user", user,
		"sessionKey", sessionKey)

	// Register the connection with the ConnectionManager
	h.connManager.RegisterConnection(sessionKey, wrappedConn)

	// Defer deregistration for when manageConnection exits
	defer func() {
		h.logger.Info(wrappedConn.Context(), "Connection management goroutine finished. Deregistering connection.", "sessionKey", sessionKey)
		h.connManager.DeregisterConnection(sessionKey)
		// Also attempt to release the session lock owned by this pod when the connection closes cleanly.
		currentPodID := h.configProvider.Get().App.PodID
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second) // Use a fresh, short-lived context
			defer releaseCancel()
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, sessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(wrappedConn.Context(), "Failed to release session lock on connection close", "sessionKey", sessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(wrappedConn.Context(), "Successfully released session lock on connection close", "sessionKey", sessionKey)
			} else {
				// This might happen if the lock expired or was taken by another session (e.g. due to kill switch)
				h.logger.Warn(wrappedConn.Context(), "Failed to release session lock on connection close (lock not held or value mismatch)", "sessionKey", sessionKey)
			}
		}
	}()

	go h.manageConnection(wsConnLifetimeCtx, wrappedConn, company, agent, user)
}

// manageConnection handles the lifecycle of a single WebSocket connection.
// It is responsible for reading messages, sending pings, handling timeouts, and ensuring cleanup.
func (h *Handler) manageConnection(connCtx context.Context, conn *Connection, companyID, agentID, userID string) {
	defer conn.Close(websocket.StatusNormalClosure, "connection ended") // Ensure WebSocket is closed

	h.logger.Info(connCtx, "WebSocket connection established successfully", "subprotocol", conn.UnderlyingConn().Subprotocol(), "remote_addr", conn.RemoteAddr())

	// FR-12: Send {"type":"ready"} message (Subtask 4.4)
	readyMessage := NewReadyMessage() // From websocket/protocol.go
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to client", "error", err.Error())
		return // Close connection via defer
	}
	h.logger.Info(connCtx, "Sent 'ready' message to client")

	appCfg := conn.config
	pingInterval := time.Duration(appCfg.PingIntervalSeconds) * time.Second
	pongWaitDuration := time.Duration(appCfg.PongWaitSeconds) * time.Second
	writeTimeout := time.Duration(appCfg.WriteTimeoutSeconds) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second // Default write timeout
	}

	if pingInterval > 0 {
		pinger := time.NewTicker(pingInterval)
		defer pinger.Stop()

		// Goroutine for sending pings periodically
		go func() {
			for {
				select {
				case <-pinger.C:
					// Create a context with timeout for the ping operation itself
					pingWriteCtx, pingCancel := context.WithTimeout(connCtx, writeTimeout)
					if err := conn.Ping(pingWriteCtx); err != nil {
						h.logger.Error(connCtx, "Failed to send ping", "error", err.Error())
						pingCancel() // Cancel the pingWriteCtx
						conn.Close(websocket.StatusAbnormalClosure, "Ping failure")
						return
					}
					pingCancel() // Release resources of pingWriteCtx
					h.logger.Debug(connCtx, "Sent ping")

					// Check for pong timeout
					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr(), "lastPong", conn.LastPongTime())
						conn.Close(websocket.StatusPolicyViolation, "Pong timeout") // 1008 StatusPolicyViolation for timeout
						return
					}
				case <-connCtx.Done():
					h.logger.Info(connCtx, "Connection context done in pinger, stopping pinger goroutine")
					return
				}
			}
		}()
	} else {
		h.logger.Warn(connCtx, "Ping interval is not configured or invalid, server-initiated pings disabled.", "configured_interval_sec", appCfg.PingIntervalSeconds)
	}

	// Main read loop with pong timeout logic
	for {
		var readCtx context.Context
		var cancelRead context.CancelFunc

		if pongWaitDuration > 0 {
			readCtx, cancelRead = context.WithTimeout(connCtx, pongWaitDuration)
		} else {
			// If no pongWaitDuration, use the connection's main context without a specific read timeout
			readCtx = connCtx
		}

		msgType, p, errRead := conn.ReadMessage(readCtx)
		if cancelRead != nil { // Always call cancel if WithTimeout was used
			cancelRead()
		}

		if errRead != nil {
			// Check if the error is due to the readCtx timeout (pong timeout)
			if errors.Is(readCtx.Err(), context.DeadlineExceeded) {
				h.logger.Warn(connCtx, "Pong timeout: No message received within pongWaitDuration. Closing connection.", "pong_wait_duration", pongWaitDuration)
				conn.Close(websocket.StatusPolicyViolation, "Pong timeout") // Or a custom code
				return                                                      // Exit manageConnection
			}

			closeStatus := websocket.CloseStatus(errRead)
			if closeStatus == websocket.StatusNormalClosure || closeStatus == websocket.StatusGoingAway {
				h.logger.Info(connCtx, "WebSocket connection closed by peer", "status_code", closeStatus)
			} else if errors.Is(errRead, context.Canceled) || connCtx.Err() == context.Canceled {
				h.logger.Info(connCtx, "WebSocket connection context canceled. Exiting manageConnection loop.")
			} else if closeStatus == -1 && (strings.Contains(strings.ToLower(errRead.Error()), "eof") || strings.Contains(strings.ToLower(errRead.Error()), "closed")) {
				// More robust check for abrupt closure or already closed connection
				h.logger.Info(connCtx, "WebSocket connection read EOF or already closed. Peer likely disconnected abruptly.", "error", errRead.Error())
			} else {
				h.logger.Error(connCtx, "Error reading from WebSocket", "error", errRead.Error(), "close_status_code", closeStatus)
			}
			return // Exit loop on any error or client close
		}
		h.logger.Debug(connCtx, "Received message from WebSocket",
			"type", msgType.String(),
			"payload_len", len(p),
		)
		// TODO: Implement actual message processing based on protocol (Subtask 4.3)
		// This is where you would unmarshal `p` into a BaseMessage, then switch on Type.
		// Example of sending an error for an unhandled type:
		if msgType == websocket.MessageText {
			var baseMsg BaseMessage
			if err := json.Unmarshal(p, &baseMsg); err != nil {
				h.logger.Error(connCtx, "Failed to unmarshal incoming message into BaseMessage", "error", err.Error())
				errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid message format", err.Error())
				if sendErr := conn.WriteJSON(NewErrorMessage(errResp)); sendErr != nil {
					h.logger.Error(connCtx, "Failed to send error message to client for invalid format", "error", sendErr.Error())
				}
				continue
			}

			switch baseMsg.Type {
			case MessageTypeSelectChat:
				var selectChatPayload SelectChatMessagePayload
				if err := json.Unmarshal(p, &selectChatPayload); err != nil {
					h.logger.Error(connCtx, "Failed to unmarshal select_chat payload", "error", err)
					errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", err.Error())
					if sendErr := conn.WriteJSON(NewErrorMessage(errorResponse)); sendErr != nil {
						h.logger.Error(connCtx, "Failed to send error message to client for select_chat", "error", sendErr.Error())
					}
					continue
				}
				h.logger.Info(connCtx, "Client selected chat", "chat_id", selectChatPayload.ChatID, "company", companyID, "agent", agentID, "user", userID)
				// TODO (FR-5): Implement dynamic route registration logic with ConnectionManager/RouteRegistry
				// e.g., h.connManager.UpdateChatSubscription(ctx, sessionKey, companyID, agentID, userID, selectChatPayload.ChatID)
			default:
				h.logger.Warn(connCtx, "Received unhandled message type from client", "type", baseMsg.Type)
				errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Unhandled message type", "Type: "+baseMsg.Type)
				if sendErr := conn.WriteJSON(NewErrorMessage(errResp)); sendErr != nil {
					h.logger.Error(connCtx, "Failed to send error message to client for unhandled type", "error", sendErr.Error())
				}
			}
		} else if msgType == websocket.MessageBinary {
			h.logger.Info(connCtx, "Received binary message, currently unhandled.")
			// Handle binary messages if necessary for your protocol
		}
	}
}
