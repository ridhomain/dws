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
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"

	"runtime/debug"

	"github.com/coder/websocket"
	"github.com/redis/go-redis/v9"

	"github.com/google/uuid"
)

// Handler handles WebSocket connections for the /ws endpoint.
type Handler struct {
	logger           domain.Logger
	configProvider   config.Provider
	connManager      *application.ConnectionManager
	natsAdapter      domain.NatsConsumer
	routeRegistry    domain.RouteRegistry
	messageForwarder domain.MessageForwarder
	redisClient      *redis.Client
}

// NewHandler creates a new WebSocket handler.
func NewHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter domain.NatsConsumer, routeRegistry domain.RouteRegistry, messageForwarder domain.MessageForwarder, redisClient *redis.Client) *Handler {
	return &Handler{
		logger:           logger,
		configProvider:   cfgProvider,
		connManager:      connManager,
		natsAdapter:      natsAdapter,
		routeRegistry:    routeRegistry,
		messageForwarder: messageForwarder,
		redisClient:      redisClient,
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
	// This context should be independent of the HTTP request's lifecycle once the connection is established.
	baseCtxForWs := context.Background()
	// Propagate essential values from the request context, like request_id.
	// Assuming RequestIDKey is the correct key used by your middleware.
	if reqID, ok := r.Context().Value(contextkeys.RequestIDKey).(string); ok && reqID != "" {
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.RequestIDKey, reqID)
		h.logger.Debug(r.Context(), "Propagated request_id to WebSocket lifetime context", "request_id", reqID)
	} else {
		// If no request ID in r.Context(), generate a new one for the WebSocket connection itself
		// This ensures the wsConnLifetimeCtx always has a request_id for logging consistency.
		newReqID := uuid.NewString()
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.RequestIDKey, newReqID)
		h.logger.Debug(r.Context(), "No request_id in r.Context(), generated new request_id for WebSocket lifetime context", "new_request_id", newReqID)
	}
	// Add other necessary context values from r.Context() to baseCtxForWs if needed.

	// Propagate authentication-related context values to the WebSocket connection's lifecycle context.
	// These are essential for operations throughout the connection's lifetime, such as session and route renewal.
	if authCtx != nil {
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.AuthUserContextKey, authCtx) // Also propagate the full authCtx if needed elsewhere
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.CompanyIDKey, authCtx.CompanyID)
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.AgentIDKey, authCtx.AgentID)
		baseCtxForWs = context.WithValue(baseCtxForWs, contextkeys.UserIDKey, authCtx.UserID)
		h.logger.Debug(r.Context(), "Propagated CompanyID, AgentID, UserID from authCtx to WebSocket lifetime context",
			"company_id", authCtx.CompanyID, "agent_id", authCtx.AgentID, "user_id", authCtx.UserID)
	} else {
		// This case should ideally be prevented by the check for authCtx earlier,
		// but as a safeguard, log if it's still nil here.
		h.logger.Error(r.Context(), "authCtx is nil when attempting to propagate its values to WebSocket lifetime context. This is unexpected.")
		// Depending on policy, might need to abort connection if critical auth info cannot be propagated.
		// For now, proceeding will likely lead to issues downstream (like the renewal errors).
	}

	wsConnLifetimeCtx, cancelWsConnLifetimeCtx := context.WithCancel(baseCtxForWs)

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
		metrics.IncrementSessionConflicts("user") // User session conflict
		domain.NewErrorResponse(domain.ErrSessionConflict, "Session already active elsewhere.", "").WriteJSON(w, http.StatusConflict)
		cancelWsConnLifetimeCtx() // Important: cancel before returning
		return
	}

	// If lock acquired, proceed to upgrade.
	sessionKey := rediskeys.SessionKey(authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	h.logger.Info(r.Context(), "Session lock successfully acquired, proceeding to WebSocket upgrade", "sessionKey", sessionKey)

	var wrappedConn *Connection // Declare wrappedConn here to be accessible for OnPongReceived
	startTime := time.Now()     // For connection duration metric

	appSpecificConfig := h.configProvider.Get().App

	var wrappedConnPtr **Connection = &wrappedConn

	opts := websocket.AcceptOptions{
		Subprotocols:       []string{"json.v1"},
		InsecureSkipVerify: appSpecificConfig.WebsocketDevelopmentInsecureSkipVerify,
		OnPongReceived: func(ctx context.Context, pongPayload []byte) {
			if *wrappedConnPtr != nil {
				h.logger.Debug((*wrappedConnPtr).Context(), "Pong received via AcceptOptions callback")
				(*wrappedConnPtr).UpdateLastPongTime()
			} else {
				h.logger.Warn(ctx, "Pong received but wrappedConn not yet initialized")
			}
		},
	}

	switch strings.ToLower(appSpecificConfig.WebsocketCompressionMode) {
	case "context_takeover":
		opts.CompressionMode = websocket.CompressionContextTakeover
		h.logger.Info(r.Context(), "WebSocket compression enabled: context_takeover")
	case "no_context_takeover":
		opts.CompressionMode = websocket.CompressionNoContextTakeover
		h.logger.Info(r.Context(), "WebSocket compression enabled: no_context_takeover")
	case "disabled":
		opts.CompressionMode = websocket.CompressionDisabled
		h.logger.Info(r.Context(), "WebSocket compression disabled by configuration.")
	default:
		opts.CompressionMode = websocket.CompressionDisabled // Default to disabled if invalid config value
		h.logger.Warn(r.Context(), "Invalid WebSocket compression mode in config, defaulting to disabled.", "configured_mode", appSpecificConfig.WebsocketCompressionMode)
	}

	if opts.CompressionMode != websocket.CompressionDisabled {
		opts.CompressionThreshold = appSpecificConfig.WebsocketCompressionThreshold
		h.logger.Info(r.Context(), "WebSocket compression threshold set", "threshold_bytes", opts.CompressionThreshold)
	}

	if appSpecificConfig.WebsocketDevelopmentInsecureSkipVerify {
		opts.InsecureSkipVerify = true
		h.logger.Warn(r.Context(), "WebSocket InsecureSkipVerify ENABLED for development. DO NOT USE IN PRODUCTION.")
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
	metrics.IncrementConnectionsTotal() // Increment total connections on successful handshake

	// Assign to wrappedConn *after* successful upgrade and *before* manageConnection so callback can use it.
	wrappedConn = NewConnection(wsConnLifetimeCtx, cancelWsConnLifetimeCtx, c, r.RemoteAddr, h.logger, h.configProvider, sessionKey)

	h.logger.Info(wrappedConn.Context(), "WebSocket connection established",
		"remoteAddr", wrappedConn.RemoteAddr(),
		"subprotocol", c.Subprotocol(),
		"company", authCtx.CompanyID,
		"agent", authCtx.AgentID,
		"user", authCtx.UserID,
		"sessionKey", sessionKey)

	// --- START ADDITION ---
	debugCompanyID, _ := wrappedConn.Context().Value(contextkeys.CompanyIDKey).(string)
	debugAgentID, _ := wrappedConn.Context().Value(contextkeys.AgentIDKey).(string)
	h.logger.Debug(wrappedConn.Context(), "DEBUG: Pre-RegisterConnection context check",
		"debug_company_id_from_conn_ctx", debugCompanyID,
		"debug_agent_id_from_conn_ctx", debugAgentID,
		"sessionKey", sessionKey)
	// --- END ADDITION ---

	// Pass companyID and agentID for route registration
	h.connManager.RegisterConnection(sessionKey, wrappedConn, authCtx.CompanyID, authCtx.AgentID)

	// Record initial activity for the session
	if h.connManager.SessionLocker() != nil {
		adaptiveSessionCfg := h.configProvider.Get().AdaptiveTTL.SessionLock
		activityTTL := time.Duration(adaptiveSessionCfg.MaxTTLSeconds) * time.Second
		if activityTTL <= 0 {
			activityTTL = time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second * 2
		}
		if errAct := h.connManager.SessionLocker().RecordActivity(wrappedConn.Context(), sessionKey, activityTTL); errAct != nil {
			h.logger.Error(wrappedConn.Context(), "Failed to record initial session activity", "sessionKey", sessionKey, "error", errAct)
		} else {
			h.logger.Debug(wrappedConn.Context(), "Recorded initial session activity", "sessionKey", sessionKey, "activityTTL", activityTTL.String())
		}
	}

	// It will execute when the safego.Execute goroutine (running manageConnection) finishes.
	defer func() {
		h.logger.Info(wrappedConn.Context(), "Connection management lifecycle ending. Deregistering connection.", "sessionKey", sessionKey)
		duration := time.Since(startTime) // startTime is from ServeHTTP's scope
		metrics.ObserveConnectionDuration(duration.Seconds())
		h.connManager.DeregisterConnection(sessionKey)
		// The lock release is handled by DeregisterConnection.
		cancelWsConnLifetimeCtx() // Ensure context is cancelled as ServeHTTP exits.
	}()

	// Call manageConnection directly.
	// Panic recovery is integrated here, similar to what safego.Execute provided.
	defer func() {
		if r := recover(); r != nil {
			logCtx := wsConnLifetimeCtx
			if wsConnLifetimeCtx.Err() != nil {
				logCtx = context.Background()
			}
			h.logger.Error(logCtx, fmt.Sprintf("Panic recovered in WebSocketConnectionManager-%s", sessionKey),
				"panic_info", fmt.Sprintf("%v", r),
				"stacktrace", string(debug.Stack()),
			)
			// Ensure connection is closed and deregistered on panic within manageConnection
			// wrappedConn.Close() might be redundant if panic was due to conn error, but good for safety.
			// Deregistration is handled by the outer defer.
		}
	}()

	// When manageConnection returns, the defers in ServeHTTP will be triggered.
	h.manageConnection(wsConnLifetimeCtx, wrappedConn, authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
}

// manageConnection handles the lifecycle of a single WebSocket connection.
// It is responsible for reading messages, sending pings, handling timeouts, and ensuring cleanup.
// The connCtx passed here is wsConnLifetimeCtx from ServeHTTP.
// companyID, agentID, userID are authoritative, derived from the validated token.
func (h *Handler) manageConnection(connCtx context.Context, conn *Connection, companyID, agentID, userID string) {
	h.logger.Info(connCtx, "WebSocket connection management started",
		"company_id", companyID,
		"agent_id", agentID,
		"user_id", userID)

	// Send ready message
	readyMessage := domain.NewReadyMessage()
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to client", "error", err.Error())
		return
	}
	metrics.IncrementMessagesSent(domain.MessageTypeReady)
	h.logger.Info(connCtx, "Sent 'ready' message to client")

	if h.redisClient != nil {
		sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
		chatSelectionKey := fmt.Sprintf("%s:selected_chat", sessionKey)

		if savedChatID, err := h.redisClient.Get(connCtx, chatSelectionKey).Result(); err == nil && savedChatID != "" {
			conn.SetCurrentChatID(savedChatID)
			h.logger.Info(connCtx, "Restored previous chat selection from Redis",
				"chat_id", savedChatID,
				"user_id", userID)

			// Also register the message route for this chat
			if h.routeRegistry != nil {
				podID := h.configProvider.Get().Server.PodID
				routeTTL := time.Duration(h.configProvider.Get().App.RouteTTLSeconds) * time.Second

				if err := h.routeRegistry.RegisterMessageRoute(connCtx, companyID, agentID, savedChatID, podID, routeTTL); err != nil {
					h.logger.Error(connCtx, "Failed to register message route for restored chat",
						"error", err.Error(),
						"chat_id", savedChatID)
				} else {
					h.logger.Debug(connCtx, "Registered message route for restored chat",
						"chat_id", savedChatID,
						"route_ttl", routeTTL)
				}
			}
		} else if err != redis.Nil {
			h.logger.Debug(connCtx, "No previous chat selection found",
				"error", err,
				"key", chatSelectionKey)
		}
	}

	// NO MORE NATS SUBSCRIPTIONS HERE!
	// The global consumer handles all NATS messages

	// Setup ping/pong handling (unchanged)
	appCfg := conn.config
	pingInterval := time.Duration(appCfg.PingIntervalSeconds) * time.Second
	pongWaitDuration := time.Duration(appCfg.PongWaitSeconds) * time.Second
	writeTimeout := time.Duration(appCfg.WriteTimeoutSeconds) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}

	if pingInterval > 0 {
		safego.Execute(connCtx, h.logger, fmt.Sprintf("WebSocketPinger-%s", conn.RemoteAddr()), func() {
			ticker := time.NewTicker(pingInterval)
			defer ticker.Stop()

			for {
				select {
				case <-connCtx.Done():
					h.logger.Info(connCtx, "Connection context done in pinger, stopping pinger goroutine")
					return
				case <-ticker.C:
					// Check if writer is still running before attempting ping
					if !conn.IsWriterRunning() {
						h.logger.Warn(connCtx, "Writer not running, stopping pinger", "remoteAddr", conn.RemoteAddr())
						return
					}

					writeCtx, writeCancel := context.WithTimeout(connCtx, writeTimeout)
					err := conn.Ping(writeCtx)
					writeCancel()

					if err != nil {
						h.logger.Error(connCtx, "Failed to send PING frame", "error", err.Error())
						// Don't try to send error message if writer is not running
						if conn.IsWriterRunning() {
							errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to send ping", err.Error())
							conn.CloseWithError(errResp, "Ping write failure")
						} else {
							// Just close the connection directly
							conn.Close(websocket.StatusInternalError, "Ping failure")
						}
						return
					}

					h.logger.Debug(connCtx, "Sent ping frame")

					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr())
						if conn.IsWriterRunning() {
							errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No pong responses received")
							conn.CloseWithError(errResp, "Pong timeout")
						} else {
							conn.Close(websocket.StatusGoingAway, "Pong timeout")
						}
						return
					}
				}
			}
		})
	}

	// Main read loop - only handles client messages now
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
			// Error handling (unchanged)
			if errors.Is(readCtx.Err(), context.DeadlineExceeded) {
				h.logger.Warn(connCtx, "Pong timeout: No message received within pongWaitDuration")
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No message received")
				conn.CloseWithError(errResp, "Pong timeout")
				return
			}

			closeStatus := websocket.CloseStatus(errRead)
			if closeStatus == websocket.StatusNormalClosure || closeStatus == websocket.StatusGoingAway {
				h.logger.Info(connCtx, "WebSocket connection closed by peer", "status_code", closeStatus)
			} else if errors.Is(errRead, context.Canceled) || connCtx.Err() == context.Canceled {
				h.logger.Info(connCtx, "WebSocket connection context canceled")
			} else {
				h.logger.Error(connCtx, "Error reading from WebSocket", "error", errRead.Error())
			}
			return
		}

		if msgType == websocket.MessageText {
			var baseMsg domain.BaseMessage
			if err := json.Unmarshal(p, &baseMsg); err != nil {
				h.logger.Error(connCtx, "Failed to unmarshal incoming message", "error", err.Error())
				errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid message format", err.Error())
				if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
					h.logger.Error(connCtx, "Failed to send error message to client", "error", sendErr.Error())
				} else {
					metrics.IncrementMessagesSent(domain.MessageTypeError)
				}
				metrics.IncrementMessagesReceived("invalid_json")
				continue
			}
			metrics.IncrementMessagesReceived(baseMsg.Type)

			switch baseMsg.Type {
			case domain.MessageTypeSelectChat:
				h.logger.Info(connCtx, "Handling select_chat message type")
				if err := h.handleSelectChatMessage(connCtx, conn, companyID, agentID, userID, baseMsg.Payload); err != nil {
					h.logger.Error(connCtx, "Error handling select_chat message", "error", err.Error())
					errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to process chat selection", err.Error())
					if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
						h.logger.Error(connCtx, "Failed to send error to client", "error", sendErr.Error())
					} else {
						metrics.IncrementMessagesSent(domain.MessageTypeError)
					}
				}
			case domain.MessageTypeReady:
				h.logger.Info(connCtx, "Received 'ready' message from client. Echoing back.")
				if err := conn.WriteJSON(baseMsg); err != nil {
					h.logger.Error(connCtx, "Failed to echo 'ready' message to client", "error", err.Error())
				} else {
					metrics.IncrementMessagesSent(domain.MessageTypeReady)
				}
			default:
				h.logger.Warn(connCtx, "Received unhandled message type", "type", baseMsg.Type)
				h.handleUnknownMessage(connCtx, conn, baseMsg)
			}
		}
	}
}

// Simplified handleSelectChatMessage - no NATS subscription management
func (h *Handler) handleSelectChatMessage(
	connCtx context.Context,
	conn *Connection,
	companyID, agentID, userID string,
	payloadData interface{},
) error {
	payloadMap, ok := payloadData.(map[string]interface{})
	if !ok {
		h.logger.Error(connCtx, "Invalid payload structure for select_chat")
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload structure", "Expected a JSON object")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return fmt.Errorf("invalid payload structure")
	}

	chatIDInterface, found := payloadMap["chat_id"]
	if !found {
		h.logger.Error(connCtx, "chat_id missing from select_chat payload")
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", "chat_id is missing")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return fmt.Errorf("chat_id missing from payload")
	}

	chatID, ok := chatIDInterface.(string)
	if !ok || chatID == "" {
		h.logger.Error(connCtx, "Invalid chat_id type or empty")
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", "chat_id must be a non-empty string")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return fmt.Errorf("invalid chat_id type or empty")
	}

	h.logger.Info(connCtx, "Client selected chat", "chat_id", chatID, "company", companyID, "agent", agentID, "user", userID)

	oldChatID := conn.GetCurrentChatID()
	if oldChatID == chatID {
		h.logger.Info(connCtx, "Client selected the same chat_id, no changes needed", "chatID", chatID)
		return nil
	}

	// Update the connection's current chat ID
	conn.SetCurrentChatID(chatID)
	h.logger.Info(connCtx, "Updated current chat ID for connection", "newChatID", chatID, "oldChatID", oldChatID)

	if h.redisClient != nil {
		sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
		chatSelectionKey := fmt.Sprintf("%s:selected_chat", sessionKey)

		// Use same TTL as session
		sessionTTL := time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second

		if err := h.redisClient.Set(connCtx, chatSelectionKey, chatID, sessionTTL).Err(); err != nil {
			h.logger.Error(connCtx, "Failed to persist chat selection in Redis",
				"key", chatSelectionKey,
				"chat_id", chatID,
				"error", err.Error())
		} else {
			h.logger.Debug(connCtx, "Persisted chat selection to Redis",
				"key", chatSelectionKey,
				"chat_id", chatID,
				"ttl", sessionTTL)
		}
	}

	// NO MORE NATS SUBSCRIPTION CHANGES!
	// The global consumer will filter messages based on GetCurrentChatID()

	// Record activity
	if h.connManager != nil && h.connManager.SessionLocker() != nil {
		sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
		adaptiveSessionCfg := h.configProvider.Get().AdaptiveTTL.SessionLock
		activityTTL := time.Duration(adaptiveSessionCfg.MaxTTLSeconds) * time.Second
		if activityTTL <= 0 {
			activityTTL = time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second * 2
		}
		if errAct := h.connManager.SessionLocker().RecordActivity(connCtx, sessionKey, activityTTL); errAct != nil {
			h.logger.Error(connCtx, "Failed to record session activity after select_chat", "sessionKey", sessionKey, "error", errAct)
		}
	}

	return nil
}

// handleUnknownMessage processes incoming messages of an unknown type.
func (h *Handler) handleUnknownMessage(connCtx context.Context, conn *Connection, baseMsg domain.BaseMessage) {
	h.logger.Warn(connCtx, "Received unhandled message type from client", "type", baseMsg.Type)
	errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Unhandled message type", "Type: "+baseMsg.Type)
	if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
		h.logger.Error(connCtx, "Failed to send error message to client for unhandled type", "error", sendErr.Error())
	} else {
		metrics.IncrementMessagesSent(domain.MessageTypeError)
	}
}
