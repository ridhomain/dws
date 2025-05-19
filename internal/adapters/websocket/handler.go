package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	// "time" // Not strictly needed for basic upgrade, can be added for timeouts later

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
	appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats"
)

// Handler handles WebSocket connection upgrades and subsequent communication.
type Handler struct {
	logger         domain.Logger
	configProvider config.Provider
	connManager    *application.ConnectionManager
	natsAdapter    *appnats.ConsumerAdapter
	// Future dependencies: connectionManager domain.ConnectionManager
}

// NewHandler creates a new WebSocket Handler.
func NewHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter *appnats.ConsumerAdapter) *Handler {
	return &Handler{
		logger:         logger,
		configProvider: cfgProvider,
		connManager:    connManager,
		natsAdapter:    natsAdapter,
	}
}

// ServeHTTP is the entry point for WebSocket upgrade requests.
// It expects to be called after authentication middleware (APIKeyAuth, CompanyTokenAuth).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pathCompany := r.PathValue("company")
	pathAgent := r.PathValue("agent")
	// user query param is no longer the primary source of user ID, but can be logged.
	queryUser := r.URL.Query().Get("user")
	token := r.URL.Query().Get("token") // Token is for CompanyTokenAuth, good to log its presence

	// Retrieve AuthenticatedUserContext injected by CompanyTokenAuthMiddleware
	authCtx, ok := r.Context().Value(contextkeys.AuthUserContextKey).(*domain.AuthenticatedUserContext)
	if !ok || authCtx == nil {
		h.logger.Error(r.Context(), "AuthenticatedUserContext not found after middleware chain",
			"path_company", pathCompany, "path_agent", pathAgent, "query_user", queryUser, "token_present", token != "",
		)
		// This should ideally not happen if middleware is correctly configured and run.
		// If it does, it's an internal server error because the auth context is missing.
		domain.NewErrorResponse(domain.ErrInternal, "Authentication context missing", "Server configuration error or middleware issue.").WriteJSON(w, http.StatusInternalServerError)
		return
	}

	// Now, the authoritative identifiers come from the token.
	// Path parameters (company, agent) might be used for resource identification or routing logic,
	// but the user's identity (authCtx.CompanyID, authCtx.AgentID, authCtx.UserID) comes from the validated token.
	// For session locking and identification, always use values from authCtx.

	if pathCompany == "" || pathAgent == "" { // Still validate path params for resource routing
		h.logger.Warn(r.Context(), "WebSocket upgrade failed: Missing company or agent in path",
			"remote_addr", r.RemoteAddr, "path", r.URL.Path,
			"auth_company_id", authCtx.CompanyID, "auth_agent_id", authCtx.AgentID, "auth_user_id", authCtx.UserID,
		)
		domain.NewErrorResponse(domain.ErrBadRequest, "Missing company or agent in path parameters.", "Ensure path is /ws/{company}/{agent}").WriteJSON(w, http.StatusBadRequest)
		return
	}

	// Optional: Log if path params differ from token claims, might indicate a misconfiguration or specific intent.
	if pathCompany != authCtx.CompanyID || pathAgent != authCtx.AgentID {
		h.logger.Warn(r.Context(), "Path parameters differ from token claims",
			"path_company", pathCompany, "token_company_id", authCtx.CompanyID,
			"path_agent", pathAgent, "token_agent_id", authCtx.AgentID,
			"token_user_id", authCtx.UserID,
		)
		// Depending on security policy, you might deny the connection here or proceed using token data as authoritative.
		// For now, we'll proceed, using token data as authoritative for the session.
	}

	// Create a new context for this specific WebSocket connection's lifecycle.
	// This context will be passed to the Connection wrapper.
	// It's derived from r.Context() initially to carry over request-scoped values like request_id.
	// However, its lifecycle is independent of the HTTP request once the connection is established.
	wsConnLifetimeCtx, cancelWsConnLifetimeCtx := context.WithCancel(r.Context())

	// Session Lock Acquisition (FR-4 part 1)
	// This context should be short-lived for the lock acquisition attempt.
	lockAcqCtx, lockAcqCancel := context.WithTimeout(r.Context(), 5*time.Second) // Example timeout
	defer lockAcqCancel()

	acquired, err := h.connManager.AcquireSessionLockOrNotify(lockAcqCtx, authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	if err != nil {
		h.logger.Error(r.Context(), "Failed during session lock acquisition attempt", "error", err,
			"company", authCtx.CompanyID, "agent", authCtx.AgentID, "user", authCtx.UserID)
		domain.NewErrorResponse(domain.ErrInternal, "Failed to process session.", err.Error()).WriteJSON(w, http.StatusInternalServerError)
		cancelWsConnLifetimeCtx() // Important: cancel the context we created if we're aborting
		return
	}
	if !acquired {
		h.logger.Warn(r.Context(), "Session lock not acquired (conflict or notification sent)",
			"company", authCtx.CompanyID, "agent", authCtx.AgentID, "user", authCtx.UserID)
		// Send a specific WebSocket close code if we could upgrade, or HTTP error if pre-upgrade.
		// For now, sending HTTP 409 Conflict as an example. The PRD implies the kill happens on the *other* client.
		// This new connection should be denied.
		domain.NewErrorResponse(domain.ErrSessionConflict, "Session already active elsewhere.", "").WriteJSON(w, http.StatusConflict)
		cancelWsConnLifetimeCtx() // Important: cancel before returning
		return
	}

	// If lock acquired, proceed to upgrade.
	sessionKey := rediskeys.SessionKey(authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
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
		h.logger.Error(r.Context(), "WebSocket upgrade failed", "error", err,
			"company", authCtx.CompanyID, "agent", authCtx.AgentID, "user", authCtx.UserID)
		// No HTTP response can be written here as hijack already happened or failed.
		// Release the lock as we failed to establish the connection for this sessionKey
		// This requires the current PodID which should be available in config.
		currentPodID := h.configProvider.Get().Server.PodID
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
		"company", authCtx.CompanyID,
		"agent", authCtx.AgentID,
		"user", authCtx.UserID,
		"sessionKey", sessionKey)

	// Pass companyID and agentID for route registration
	h.connManager.RegisterConnection(sessionKey, wrappedConn, authCtx.CompanyID, authCtx.AgentID)

	// Defer deregistration for when manageConnection exits
	defer func() {
		h.logger.Info(wrappedConn.Context(), "Connection management goroutine finished. Deregistering connection.", "sessionKey", sessionKey)
		h.connManager.DeregisterConnection(sessionKey)
		// Also attempt to release the session lock owned by this pod when the connection closes cleanly.
		currentPodID := h.configProvider.Get().Server.PodID
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second) // Use a fresh, short-lived context
			defer releaseCancel()
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, sessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(wrappedConn.Context(), "Failed to release session lock on connection close", "sessionKey", sessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(wrappedConn.Context(), "Successfully released session lock on connection close", "sessionKey", sessionKey)
			} else {
				// This might happen if the lock expired or was taken by another session (e.g. due to kill switch)
				h.logger.Warn(wrappedConn.Context(), "Failed to release session lock on connection close (lock not held or value mismatch)", "sessionKey", sessionKey, "pod_id_used_for_release", currentPodID)
			}
		}
	}()

	safego.Execute(wsConnLifetimeCtx, h.logger, fmt.Sprintf("WebSocketConnectionManager-%s", sessionKey), func() {
		h.manageConnection(wsConnLifetimeCtx, wrappedConn, authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	})
}

// manageConnection handles the lifecycle of a single WebSocket connection.
// It is responsible for reading messages, sending pings, handling timeouts, and ensuring cleanup.
// The companyID, agentID, and userID parameters are now authoritative, derived from the validated token.
func (h *Handler) manageConnection(connCtx context.Context, conn *Connection, companyID, agentID, userID string) {
	defer conn.Close(websocket.StatusNormalClosure, "connection ended") // Ensure WebSocket is closed

	// Use the authenticated IDs for logging here
	h.logger.Info(connCtx, "WebSocket connection management started",
		"subprotocol", conn.UnderlyingConn().Subprotocol(),
		"remote_addr", conn.RemoteAddr(),
		"company_id", companyID,
		"agent_id", agentID,
		"user_id", userID)

	// FR-12: Send {"type":"ready"} message (Subtask 4.4)
	readyMessage := NewReadyMessage() // From websocket/protocol.go
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to client", "error", err.Error())
		return // Close connection via defer
	}
	h.logger.Info(connCtx, "Sent 'ready' message to client")

	// NATS Subscription (Subtask 6.2)
	var natsSubscription *nats.Subscription
	if h.natsAdapter != nil {
		// Define the message handler for NATS messages
		natsMsgHandler := func(msg *nats.Msg) {
			h.logger.Info(connCtx, "Received NATS message", "subject", msg.Subject, "data_len", len(msg.Data))
			var eventPayload domain.EnrichedEventPayload // Using placeholder from domain/nats_payloads.go
			if err := json.Unmarshal(msg.Data, &eventPayload); err != nil {
				h.logger.Error(connCtx, "Failed to unmarshal NATS message into EnrichedEventPayload",
					"subject", msg.Subject, "error", err.Error(), "raw_data", string(msg.Data)) // Log raw data for debugging
				// Ack message even if unmarshalling fails to prevent redelivery of bad messages.
				// Alternatively, could Nack or let it timeout if redelivery of malformed messages is desired for some reason.
				if ackErr := msg.Ack(); ackErr != nil {
					h.logger.Error(connCtx, "Failed to ACK NATS message after unmarshal error", "subject", msg.Subject, "error", ackErr.Error())
				}
				return
			}

			// Construct the WebSocket message
			wsMessage := NewEventMessage(eventPayload) // NewEventMessage is in websocket/protocol.go

			if err := conn.WriteJSON(wsMessage); err != nil {
				h.logger.Error(connCtx, "Failed to forward NATS message to WebSocket client",
					"subject", msg.Subject, "event_id", eventPayload.EventID, "error", err.Error(),
				)
				// If writing to WebSocket fails, the connection might be dead.
				// The NATS message should probably not be acked here, to allow redelivery if the consumer (this pod/ws connection)
				// dies before processing. However, if the message is "processed" by attempting a send,
				// and the failure is WS-specific, acking might be okay to prevent re-processing by a *new* session for this user.
				// For now, let's try to ack. If the issue is persistent, the message might be acked without reaching client.
				// A more robust solution might involve dead-letter queues or more sophisticated retry logic.
			}

			// Ack the NATS message after processing (or attempting to process)
			if ackErr := msg.Ack(); ackErr != nil {
				h.logger.Error(connCtx, "Failed to ACK NATS message after processing", "subject", msg.Subject, "event_id", eventPayload.EventID, "error", ackErr.Error())
			}
		}

		var subErr error
		natsSubscription, subErr = h.natsAdapter.SubscribeToChats(connCtx, companyID, agentID, natsMsgHandler)
		if subErr != nil {
			h.logger.Error(connCtx, "Failed to subscribe to NATS chat subject",
				"companyID", companyID, "agentID", agentID, "error", subErr.Error(),
			)
			// Decide if this is fatal for the WS connection. For now, log and continue without NATS.
			// Alternatively, close the WS connection with an error.
			// conn.WriteJSON(NewErrorMessage(domain.NewErrorResponse(domain.ErrSubscriptionFailure, "Could not subscribe to backend events.", subErr.Error())))
			// conn.Close(websocket.StatusInternalError, "Subscription failure")
			// return
		} else {
			h.logger.Info(connCtx, "Successfully subscribed to NATS chat subject", "companyID", companyID, "agentID", agentID)
			defer func() {
				if natsSubscription != nil {
					h.logger.Info(connCtx, "Unsubscribing from NATS chat subject", "subject", natsSubscription.Subject)
					if unsubErr := natsSubscription.Drain(); unsubErr != nil { // Drain is preferred for graceful unsubscribe
						h.logger.Error(connCtx, "Error draining NATS subscription", "subject", natsSubscription.Subject, "error", unsubErr.Error())
					}
				}
			}()
		}
	} else {
		h.logger.Warn(connCtx, "NATS adapter is not available, cannot subscribe to chat events.")
	}

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
		safego.Execute(connCtx, conn.logger, fmt.Sprintf("WebSocketPinger-%s", conn.RemoteAddr()), func() {
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
		})
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
				h.logger.Info(connCtx, "Handling select_chat message type")
				h.handleSelectChatMessage(connCtx, conn, p, companyID, agentID, userID, baseMsg.Payload)
			default:
				h.logger.Warn(connCtx, "Handling unknown message type", "type", baseMsg.Type)
				h.handleUnknownMessage(connCtx, conn, baseMsg)
			}
		} else if msgType == websocket.MessageBinary {
			h.logger.Info(connCtx, "Received binary message, currently unhandled.")
			// Handle binary messages if necessary for your protocol
		}
	}
}

// handleSelectChatMessage processes incoming messages of type MessageTypeSelectChat.
// It now accepts the already unmarshalled payload to avoid double unmarshalling.
func (h *Handler) handleSelectChatMessage(connCtx context.Context, conn *Connection, rawPayload []byte, companyID, agentID, userID string, payloadData interface{}) {
	// The payloadData is expected to be a map[string]interface{} due to initial unmarshal into BaseMessage
	payloadMap, ok := payloadData.(map[string]interface{})
	if !ok {
		h.logger.Error(connCtx, "Invalid payload structure for select_chat after initial unmarshal", "type_received", fmt.Sprintf("%T", payloadData))
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload structure", "Expected a JSON object as payload.")
		if sendErr := conn.WriteJSON(NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for select_chat structure", "error", sendErr.Error())
		}
		return
	}

	chatIDInterface, found := payloadMap["chat_id"]
	if !found {
		h.logger.Error(connCtx, "chat_id missing from select_chat payload map", "company", companyID, "agent", agentID, "user", userID)
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", "chat_id is missing.")
		if sendErr := conn.WriteJSON(NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for missing chat_id", "error", sendErr.Error())
		}
		return
	}

	chatID, ok := chatIDInterface.(string)
	if !ok || chatID == "" {
		h.logger.Error(connCtx, "Invalid chat_id type or empty in select_chat payload", "type_received", fmt.Sprintf("%T", chatIDInterface), "value", chatIDInterface, "company", companyID, "agent", agentID, "user", userID)
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", "chat_id must be a non-empty string.")
		if sendErr := conn.WriteJSON(NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for invalid chat_id type", "error", sendErr.Error())
		}
		return
	}

	h.logger.Info(connCtx, "Client selected chat", "chat_id", chatID, "company", companyID, "agent", agentID, "user", userID)

	// --- Subtask 7.4: Message Route Management Logic ---
	cfg := h.configProvider.Get()
	podID := cfg.Server.PodID
	routeTTL := time.Duration(cfg.App.RouteTTLSeconds) * time.Second
	if routeTTL <= 0 {
		routeTTL = 30 * time.Second // Default if not configured
		h.logger.Warn(connCtx, "RouteTTLSeconds not configured or zero, using default 30s for message route registration", "newChatID", chatID)
	}

	if podID == "" {
		h.logger.Error(connCtx, "PodID is not configured. Cannot manage message routes.", "newChatID", chatID)
		// Optionally send an error back to the client
		errorResponse := domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Cannot process chat selection due to server misconfiguration.")
		if sendErr := conn.WriteJSON(NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for podID config error", "error", sendErr.Error())
		}
		return
	}

	routeReg := h.connManager.RouteRegistrar()
	if routeReg == nil {
		h.logger.Error(connCtx, "RouteRegistry is not available in ConnectionManager. Cannot manage message routes.", "newChatID", chatID)
		// Optionally send an error back to the client
		errorResponse := domain.NewErrorResponse(domain.ErrInternal, "Server error", "Cannot process chat selection due to server error.")
		if sendErr := conn.WriteJSON(NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for RouteRegistry nil error", "error", sendErr.Error())
		}
		return
	}

	// 1. Retrieve Old Chat ID
	oldChatID := conn.GetCurrentChatID()

	// 2. Unregister Old Message Route (if an old chat ID existed and is different from the new one)
	if oldChatID != "" && oldChatID != chatID {
		h.logger.Info(connCtx, "Unregistering old message route", "oldChatID", oldChatID, "podID", podID)
		if err := routeReg.UnregisterMessageRoute(connCtx, companyID, agentID, oldChatID, podID); err != nil {
			h.logger.Error(connCtx, "Failed to unregister old message route",
				"oldChatID", oldChatID, "podID", podID, "error", err.Error(),
			)
			// Continue to register the new one, but log the error
		} else {
			h.logger.Info(connCtx, "Successfully unregistered old message route", "oldChatID", oldChatID)
		}
	}

	// 3. Register New Message Route (only if it's different from the old one or if there was no old one)
	if oldChatID != chatID {
		h.logger.Info(connCtx, "Registering new message route", "newChatID", chatID, "podID", podID, "ttl", routeTTL.String())
		if err := routeReg.RegisterMessageRoute(connCtx, companyID, agentID, chatID, podID, routeTTL); err != nil {
			h.logger.Error(connCtx, "Failed to register new message route",
				"newChatID", chatID, "podID", podID, "error", err.Error(),
			)
			// Optionally send an error back to the client
			errorResponse := domain.NewErrorResponse(domain.ErrInternal, "Failed to select chat", "Could not update message subscription.")
			if sendErr := conn.WriteJSON(NewErrorMessage(errorResponse)); sendErr != nil {
				h.logger.Error(connCtx, "Failed to send error message to client for new route registration failure", "error", sendErr.Error())
			}
			// Do not update currentChatID if registration fails
			return
		} else {
			h.logger.Info(connCtx, "Successfully registered new message route", "newChatID", chatID)
		}
	}

	// 4. Update Stored Chat ID
	conn.SetCurrentChatID(chatID)
	h.logger.Info(connCtx, "Updated current chat ID for connection", "newChatID", chatID)

}

// handleUnknownMessage processes incoming messages of an unknown type.
func (h *Handler) handleUnknownMessage(connCtx context.Context, conn *Connection, baseMsg BaseMessage) {
	h.logger.Warn(connCtx, "Received unhandled message type from client", "type", baseMsg.Type)
	errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Unhandled message type", "Type: "+baseMsg.Type)
	if sendErr := conn.WriteJSON(NewErrorMessage(errResp)); sendErr != nil {
		h.logger.Error(connCtx, "Failed to send error message to client for unhandled type", "error", sendErr.Error())
	}
}
