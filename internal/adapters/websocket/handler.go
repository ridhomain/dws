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

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
	appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats"
	appredis "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/redis"

	"runtime/debug"

	"github.com/google/uuid"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
)

// Handler handles WebSocket connections for the /ws endpoint.
type Handler struct {
	logger           domain.Logger
	configProvider   config.Provider
	connManager      *application.ConnectionManager
	natsAdapter      domain.NatsConsumer
	routeRegistry    domain.RouteRegistry
	messageForwarder domain.MessageForwarder
}

// NewHandler creates a new WebSocket handler.
func NewHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter domain.NatsConsumer, routeRegistry domain.RouteRegistry, messageForwarder domain.MessageForwarder) *Handler {
	return &Handler{
		logger:           logger,
		configProvider:   cfgProvider,
		connManager:      connManager,
		natsAdapter:      natsAdapter,
		routeRegistry:    routeRegistry,
		messageForwarder: messageForwarder,
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

	opts := websocket.AcceptOptions{
		Subprotocols:       []string{"json.v1"},
		InsecureSkipVerify: appSpecificConfig.WebsocketDevelopmentInsecureSkipVerify,
		OnPongReceived: func(ctx context.Context, pongPayload []byte) {
			if wrappedConn != nil {
				h.logger.Debug(wrappedConn.Context(), "Pong received via AcceptOptions callback")
				wrappedConn.UpdateLastPongTime()
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
	// DO NOT add 'defer conn.Close(...)' here.
	// manageConnection's context (connCtx) will be canceled externally (e.g., by ConnectionManager or if ServeHTTP fails post-goroutine start)
	// or internally by conn.Close() if a read/write/ping error requires immediate shutdown.
	// When connCtx is Done, this function will return, and the defer in ServeHTTP will handle DeregisterConnection.

	// Use the authenticated IDs for logging here
	h.logger.Info(connCtx, "WebSocket connection management started",
		"subprotocol", conn.UnderlyingConn().Subprotocol(),
		"remote_addr", conn.RemoteAddr(),
		"company_id", companyID,
		"agent_id", agentID,
		"user_id", userID)

	readyMessage := domain.NewReadyMessage()
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to client", "error", err.Error())
		return
	}
	metrics.IncrementMessagesSent(domain.MessageTypeReady)
	h.logger.Info(connCtx, "Sent 'ready' message to client")

	// DIAGNOSTIC: Refined logging around the delay
	h.logger.Debug(connCtx, "DIAGNOSTIC: Pre-sleep check. Context error (if any)", "error_before_sleep", fmt.Sprintf("%v", connCtx.Err()))

	time.Sleep(100 * time.Millisecond)

	h.logger.Debug(connCtx, "DIAGNOSTIC: Post-sleep check. Context error (if any)", "error_after_sleep", fmt.Sprintf("%v", connCtx.Err()))

	if connCtx.Err() != nil {
		h.logger.Error(connCtx, "DIAGNOSTIC: Context WAS CANCELED during/after sleep period", "error", connCtx.Err())
		// Use a more specific reason for CloseWithError if this path is taken
		conn.CloseWithError(domain.NewErrorResponse(domain.ErrInternal, "Context canceled during diagnostic sleep", connCtx.Err().Error()), "context canceled (diag sleep)")
		return
	} else {
		h.logger.Debug(connCtx, "DIAGNOSTIC: Context OK after sleep, proceeding to NATS.")
	}

	var generalNatsSubscription domain.NatsMessageSubscription  // Changed type
	var specificNatsSubscription domain.NatsMessageSubscription // Changed type
	var currentSpecificChatID string

	// Handler for general chat events (e.g., chat list updates)
	generalChatEventsNatsHandler := func(msg *nats.Msg) {
		metrics.IncrementNatsMessagesReceived(msg.Subject)
		natsRequestID := msg.Header.Get(middleware.XRequestIDHeader)
		if natsRequestID == "" {
			natsRequestID = uuid.NewString()
		}
		msgCtx := context.WithValue(connCtx, contextkeys.RequestIDKey, natsRequestID)

		h.logger.Info(msgCtx, "Received general chat event from NATS", "subject", msg.Subject, "data_len", len(msg.Data))
		var eventPayload domain.EnrichedEventPayload
		if errUnmarshal := json.Unmarshal(msg.Data, &eventPayload); errUnmarshal != nil {
			h.logger.Error(msgCtx, "Failed to unmarshal general chat event payload", "subject", msg.Subject, "error", errUnmarshal.Error())
			return // Return to let NATS redeliver after AckWait
		}
		wsMessage := domain.NewEventMessage(eventPayload)
		if errWrite := conn.WriteJSON(wsMessage); errWrite != nil {
			h.logger.Error(msgCtx, "Failed to forward general chat event to WebSocket client", "subject", msg.Subject, "event_id", eventPayload.EventID, "error", errWrite.Error())
			return // Do not record activity if write failed
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeEvent)
			// Record session activity after successful write
			if h.connManager != nil && h.connManager.SessionLocker() != nil {
				sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
				adaptiveSessionCfg := h.configProvider.Get().AdaptiveTTL.SessionLock
				activityTTL := time.Duration(adaptiveSessionCfg.MaxTTLSeconds) * time.Second
				if activityTTL <= 0 {
					activityTTL = time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second * 2
				}
				if errAct := h.connManager.SessionLocker().RecordActivity(msgCtx, sessionKey, activityTTL); errAct != nil {
					h.logger.Error(msgCtx, "Failed to record session activity after general NATS event write", "sessionKey", sessionKey, "error", errAct)
				}
			}
		}
		_ = msg.Ack()
	}

	// Initial subscription to general wa.C.A.chats topic
	if h.natsAdapter != nil {
		var subErr error
		generalNatsSubscription, subErr = h.natsAdapter.SubscribeToChats(connCtx, companyID, agentID, generalChatEventsNatsHandler)
		if subErr != nil {
			h.logger.Error(connCtx, "Failed to subscribe to general NATS chats topic", "companyID", companyID, "agentID", agentID, "error", subErr.Error())
			errorMsg := domain.NewErrorResponse(domain.ErrSubscriptionFailure, "Could not subscribe to chat updates", subErr.Error())
			if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorMsg)); sendErr != nil {
				h.logger.Error(connCtx, "Failed to send NATS subscription error to client for general chats", "error", sendErr.Error())
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeError)
			}
			// Depending on policy, might close connection if initial subscription fails
		} else {
			h.logger.Info(connCtx, "Successfully subscribed to general NATS chats topic", "subject", generalNatsSubscription.Subject())
		}
	} else {
		h.logger.Warn(connCtx, "NATS adapter not available, cannot subscribe to general chat events.")
	}

	// Renamed specificChatNatsMessageHandler from natsMessageHandler for clarity
	specificChatNatsMessageHandler := func(msg *nats.Msg) {
		metrics.IncrementNatsMessagesReceived(msg.Subject)

		natsRequestID := msg.Header.Get(middleware.XRequestIDHeader)
		if natsRequestID == "" {
			natsRequestID = uuid.NewString()
			h.logger.Debug(connCtx, "Generated new request_id for NATS message", "subject", msg.Subject, "new_request_id", natsRequestID)
		} else {
			h.logger.Debug(connCtx, "Using existing request_id from NATS message header", "subject", msg.Subject, "request_id", natsRequestID)
		}
		msgCtx := context.WithValue(connCtx, contextkeys.RequestIDKey, natsRequestID)

		msgCompanyID, msgAgentID, msgChatID, err := appnats.ParseNATSMessageSubject(msg.Subject)
		if err != nil {
			h.logger.Error(msgCtx, "Failed to parse NATS message subject", "subject", msg.Subject, "error", err.Error())
			return // Return to let NATS redeliver after AckWait
		}

		// Debug log for NATS message receipt
		h.logger.Debug(msgCtx, "Received NATS message",
			"subject", msg.Subject,
			"company_id", msgCompanyID,
			"agent_id", msgAgentID,
			"chat_id", msgChatID,
			"data_size", len(msg.Data),
			"operation", "NatsMessageHandler")

		currentPodID := h.configProvider.Get().Server.PodID
		if currentPodID == "" {
			h.logger.Error(connCtx, "Current PodID is not configured, cannot determine message ownership.", "subject", msg.Subject)
			return // Return to let NATS redeliver after AckWait
		}

		ownerPodID, err := h.routeRegistry.GetOwningPodForMessageRoute(connCtx, msgCompanyID, msgAgentID, msgChatID)
		if err != nil {
			if errors.Is(err, appredis.ErrNoOwningPod) {
				h.logger.Warn(connCtx, "No owning pod found for message route in Redis, potential race or cleanup issue. NACKing message.", "subject", msg.Subject, "chat_id_from_subject", msgChatID)
				if nakErr := msg.Nak(); nakErr != nil {
					h.logger.Error(connCtx, "Failed to NACK NATS message for ErrNoOwningPod", "subject", msg.Subject, "error", nakErr.Error())
				}
				return // Return to let NATS redeliver after AckWait
			} else {
				h.logger.Error(connCtx, "Failed to get owning pod for message route from Redis", "subject", msg.Subject, "error", err.Error())
				return // Return to let NATS redeliver after AckWait
			}
		}

		var isOwner bool
		if ownerPodID == currentPodID {
			isOwner = true
		} else {
			isOwner = false
			if ownerPodID == "" {
				h.logger.Error(connCtx, "Internal logic inconsistency: ownerPodID is empty after GetOwningPodForMessageRoute succeeded. Assuming not owner.", "subject", msg.Subject)
			}
		}

		if isOwner {
			h.logger.Info(msgCtx, "Current pod IS THE OWNER of the message route. Delivering locally.", "subject", msg.Subject, "podID", currentPodID)
			var eventPayload domain.EnrichedEventPayload
			if errUnmarshal := json.Unmarshal(msg.Data, &eventPayload); errUnmarshal != nil {
				h.logger.Error(msgCtx, "Failed to unmarshal NATS message into EnrichedEventPayload (owner)",
					"subject", msg.Subject, "error", errUnmarshal.Error(), "raw_data", string(msg.Data))
				return // Return to let NATS redeliver after AckWait
			}

			// Check for duplicate message delivery (message uniqueness)
			// This helps prevent re-processing if a message is delivered more than once due to NATS redelivery or other reasons
			eventID := eventPayload.EventID
			if eventID != "" {
				// For now, implement a simple in-memory message deduplication check
				// In a production environment, this could be enhanced with a distributed solution like Redis

				// Create a unique key for this message in this pod
				messageKey := fmt.Sprintf("%s:%s:%s:%s", msgCompanyID, msgAgentID, msgChatID, eventID)

				// The actual deduplication check would go here
				// For now, we'll just log that we would check for duplicates
				h.logger.Debug(msgCtx, "Would check for message uniqueness (not implemented)",
					"event_id", eventID,
					"message_key", messageKey,
					"subject", msg.Subject,
					"operation", "NatsMessageHandler")
			}

			// Log delivery attempt to client
			h.logger.Debug(msgCtx, "Attempting to deliver NATS message to WebSocket client",
				"subject", msg.Subject,
				"event_id", eventPayload.EventID,
				"operation", "NatsMessageHandler")

			wsMessage := domain.NewEventMessage(eventPayload)
			if errWrite := conn.WriteJSON(wsMessage); errWrite != nil {
				h.logger.Error(msgCtx, "Failed to forward NATS message to WebSocket client (owner)",
					"subject", msg.Subject, "event_id", eventPayload.EventID, "error", errWrite.Error(),
				)
				return // Do not record activity if write failed
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeEvent)
				h.logger.Debug(msgCtx, "Successfully delivered NATS message to WebSocket client",
					"subject", msg.Subject,
					"event_id", eventPayload.EventID,
					"operation", "NatsMessageHandler")

				// Record session activity
				if h.connManager != nil && h.connManager.SessionLocker() != nil {
					sessionKey := rediskeys.SessionKey(companyID, agentID, userID) // companyID, agentID, userID are from manageConnection scope
					adaptiveSessionCfg := h.configProvider.Get().AdaptiveTTL.SessionLock
					activityTTL := time.Duration(adaptiveSessionCfg.MaxTTLSeconds) * time.Second
					if activityTTL <= 0 {
						activityTTL = time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second * 2
					}
					if errAct := h.connManager.SessionLocker().RecordActivity(msgCtx, sessionKey, activityTTL); errAct != nil {
						h.logger.Error(msgCtx, "Failed to record session activity after specific NATS event write", "sessionKey", sessionKey, "error", errAct)
					} else {
						h.logger.Debug(msgCtx, "Recorded session activity after message delivery",
							"session_key", sessionKey,
							"ttl", activityTTL.String(),
							"operation", "NatsMessageHandler")
					}
				}
				// Record message route activity
				if h.routeRegistry != nil {
					messageRouteKey := rediskeys.RouteKeyMessages(msgCompanyID, msgAgentID, msgChatID)
					adaptiveMsgRouteCfg := h.configProvider.Get().AdaptiveTTL.MessageRoute
					activityTTL := time.Duration(adaptiveMsgRouteCfg.MaxTTLSeconds) * time.Second
					if activityTTL <= 0 {
						activityTTL = time.Duration(h.configProvider.Get().App.RouteTTLSeconds) * time.Second * 2
					}
					if errAct := h.routeRegistry.RecordActivity(msgCtx, messageRouteKey, activityTTL); errAct != nil {
						h.logger.Error(msgCtx, "Failed to record message route activity after specific NATS event write (owner)", "messageRouteKey", messageRouteKey, "error", errAct)
					} else {
						h.logger.Debug(msgCtx, "Recorded message route activity after message delivery",
							"message_route_key", messageRouteKey,
							"ttl", activityTTL.String(),
							"operation", "NatsMessageHandler")
					}
				}
			}
		} else {
			h.logger.Info(msgCtx, "Current pod IS NOT THE OWNER of the message route. Attempting gRPC hop via MessageForwarder.",
				"subject", msg.Subject, "current_pod_id", currentPodID, "owner_pod_id", ownerPodID)

			if ownerPodID != "" { // Ensure there is a specific owner pod to forward to
				gprcTargetAddress := fmt.Sprintf("%s:%d", ownerPodID, h.configProvider.Get().Server.GRPCPort)
				var domainPayload domain.EnrichedEventPayload
				if errUnmarshal := json.Unmarshal(msg.Data, &domainPayload); errUnmarshal != nil {
					h.logger.Error(msgCtx, "Failed to unmarshal NATS message data for gRPC forwarding (MessageForwarder)", "subject", msg.Subject, "error", errUnmarshal.Error())
					// Do NOT ACK if unmarshal failed for forwarding logic consistency, let NATS redeliver.
					// Or, if this is a permanent error, consider a dead-letter queue strategy (outside current scope).
					return
				} else {
					h.logger.Debug(msgCtx, "Attempting to forward NATS message via gRPC",
						"subject", msg.Subject,
						"event_id", domainPayload.EventID,
						"target_address", gprcTargetAddress,
						"operation", "NatsMessageHandler")

					if errFwd := h.messageForwarder.ForwardEvent(msgCtx, gprcTargetAddress, &domainPayload, msgCompanyID, msgAgentID, msgChatID, currentPodID); errFwd != nil {
						h.logger.Error(msgCtx, "Failed to forward event via MessageForwarder", "target_address", gprcTargetAddress, "event_id", domainPayload.EventID, "error", errFwd.Error())
						// Do NOT ACK if forwarding failed
						return // Return to let NATS redeliver
					} else {
						h.logger.Debug(msgCtx, "Successfully forwarded NATS message via gRPC",
							"subject", msg.Subject,
							"event_id", domainPayload.EventID,
							"target_address", gprcTargetAddress,
							"operation", "NatsMessageHandler")
						h.logger.Info(msgCtx, "Successfully initiated event forwarding via MessageForwarder", "target_address", gprcTargetAddress, "event_id", domainPayload.EventID)
					}
				}
			} else {
				h.logger.Warn(msgCtx, "No specific owner pod ID found for gRPC hop (MessageForwarder), message will not be forwarded.", "subject", msg.Subject)
				// If not forwarded, and not owned locally, this message is effectively dropped by this pod.
				// We should still ACK it to prevent NATS redelivery if this is the terminal state for this pod.
				// However, if ErrNoOwningPod was hit earlier and NACKed, this path won't be reached for that message.
				// Assuming if ownerPodID is empty here, it's a scenario where the message shouldn't be processed by this pod.
			}
		}

		if ackErr := msg.Ack(); ackErr != nil {
			h.logger.Error(msgCtx, "Failed to ACK NATS message after processing", "subject", msg.Subject, "error", ackErr.Error())
		} else {
			h.logger.Debug(msgCtx, "Successfully ACKed NATS message",
				"subject", msg.Subject,
				"operation", "NatsMessageHandler")
		}
	}

	// Defer cleanup for all subscriptions
	defer func() {
		if generalNatsSubscription != nil && generalNatsSubscription.IsValid() { // Added IsValid check
			h.logger.Info(connCtx, "Draining general NATS subscription on connection close", "subject", generalNatsSubscription.Subject())
			if unsubErr := generalNatsSubscription.Drain(); unsubErr != nil {
				h.logger.Error(connCtx, "Error draining general NATS subscription on close", "subject", generalNatsSubscription.Subject(), "error", unsubErr.Error())
			}
		}
		if specificNatsSubscription != nil && specificNatsSubscription.IsValid() { // Added IsValid check
			h.logger.Info(connCtx, "Draining specific NATS subscription on connection close", "subject", specificNatsSubscription.Subject(), "chatID", currentSpecificChatID)
			if unsubErr := specificNatsSubscription.Drain(); unsubErr != nil {
				h.logger.Error(connCtx, "Error draining specific NATS subscription on close", "subject", specificNatsSubscription.Subject(), "error", unsubErr.Error())
			}
		}
	}()

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
					// IMPLEMENTATION CHANGE: Don't use conn.Ping() as it doesn't seem to work consistently with received PONGs
					// Instead, manually write a PING and rely on our OnPongReceived callback which updates LastPongTime()
					// We've confirmed OnPongReceived works (logs show "Pong received via AcceptOptions callback")

					// The old approach that doesn't work properly:
					// pingOpCtx, pingOpCancel := context.WithTimeout(context.Background(), 70*time.Second)
					// if err := conn.Ping(pingOpCtx); err != nil { ... }

					// New approach: just write a PING frame directly
					writeCtx, writeCancel := context.WithTimeout(connCtx, writeTimeout)

					// Get the underlying *websocket.Conn and use it to send PING directly
					wsConn := conn.UnderlyingConn()
					err := wsConn.Ping(writeCtx) // Simple ping without waiting for PONG

					writeCancel()
					if err != nil {
						h.logger.Error(connCtx, "Failed to send PING frame", "error", err.Error())
						errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to send ping", err.Error())
						conn.CloseWithError(errResp, "Ping write failure")
						return
					}

					h.logger.Debug(connCtx, "Sent ping frame manually") // Changed log to be more specific

					// This check uses OUR lastPongTime, updated by OnPongReceived callback
					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr(), "lastPong", conn.LastPongTime())
						errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No pong responses received within the configured duration.")
						conn.CloseWithError(errResp, "Pong timeout")
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
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No message received within the configured timeout period.")
				conn.CloseWithError(errResp, "Pong timeout")
				return
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
		// This is where you would unmarshal `p` into a BaseMessage, then switch on Type.
		if msgType == websocket.MessageText {
			var baseMsg domain.BaseMessage
			if err := json.Unmarshal(p, &baseMsg); err != nil {
				h.logger.Error(connCtx, "Failed to unmarshal incoming message into BaseMessage", "error", err.Error())
				errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid message format", err.Error())
				if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
					h.logger.Error(connCtx, "Failed to send error message to client for invalid format", "error", sendErr.Error())
				} else {
					metrics.IncrementMessagesSent(domain.MessageTypeError)
				}
				metrics.IncrementMessagesReceived("invalid_json") // Or a more specific type if type cannot be parsed
				continue
			}
			metrics.IncrementMessagesReceived(baseMsg.Type) // Increment after successful unmarshal and type identification

			switch baseMsg.Type {
			case domain.MessageTypeSelectChat:
				h.logger.Info(connCtx, "Handling select_chat message type")
				// Pass the natsMessageHandler and a way to update currentNatsSubscription
				newSub, newChatID, err := h.handleSelectChatMessage(connCtx, conn, companyID, agentID, userID, baseMsg.Payload, specificChatNatsMessageHandler, generalNatsSubscription, specificNatsSubscription, currentSpecificChatID)
				if err != nil {
					h.logger.Error(connCtx, "Error handling select_chat message", "error", err.Error())
					errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to process chat selection", err.Error())
					if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
						h.logger.Error(connCtx, "Failed to send error to client for select_chat failure", "error", sendErr.Error())
					} else {
						metrics.IncrementMessagesSent(domain.MessageTypeError)
					}
				} else {
					generalNatsSubscription = nil // This was incorrectly outside the successful case before
					specificNatsSubscription = newSub
					currentSpecificChatID = newChatID
					// Record session activity after successful chat selection
					if h.connManager != nil && h.connManager.SessionLocker() != nil {
						sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
						adaptiveSessionCfg := h.configProvider.Get().AdaptiveTTL.SessionLock
						activityTTL := time.Duration(adaptiveSessionCfg.MaxTTLSeconds) * time.Second
						if activityTTL <= 0 { // Fallback if MaxTTLSeconds is not set or zero
							activityTTL = time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second * 2 // Default to 2x base session TTL
						}
						if errAct := h.connManager.SessionLocker().RecordActivity(connCtx, sessionKey, activityTTL); errAct != nil {
							h.logger.Error(connCtx, "Failed to record session activity after select_chat", "sessionKey", sessionKey, "error", errAct)
						} else {
							h.logger.Debug(connCtx, "Recorded session activity after select_chat", "sessionKey", sessionKey, "activityTTL", activityTTL.String())
						}
					}
				}
			case domain.MessageTypeReady:
				h.logger.Info(connCtx, "Received 'ready' message from client. Echoing back.", "type", baseMsg.Type, "payload", baseMsg.Payload)
				// Echo the received ready message (type and payload) back to the client
				if err := conn.WriteJSON(baseMsg); err != nil {
					h.logger.Error(connCtx, "Failed to echo 'ready' message to client", "error", err.Error())
				} else {
					metrics.IncrementMessagesSent(domain.MessageTypeReady)
					h.logger.Info(connCtx, "Successfully echoed 'ready' message to client")
				}
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
// It also takes the NATS message handler and the current NATS subscription to manage transitions.
func (h *Handler) handleSelectChatMessage(
	connCtx context.Context,
	conn *Connection,
	companyID, agentID, userID string,
	payloadData interface{},
	specificChatNatsMsgHandler domain.NatsMessageHandler, // Changed type
	currentGeneralSub domain.NatsMessageSubscription, // Changed type
	currentSpecificSub domain.NatsMessageSubscription, // Changed type
	currentSpecificSubChatID string,
) (domain.NatsMessageSubscription, string, error) { // Changed return type

	payloadMap, ok := payloadData.(map[string]interface{})
	if !ok {
		h.logger.Error(connCtx, "Invalid payload structure for select_chat after initial unmarshal", "type_received", fmt.Sprintf("%T", payloadData))
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload structure", "Expected a JSON object as payload.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for select_chat structure", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("invalid payload structure") // Return current sub and old chatID on error
	}

	chatIDInterface, found := payloadMap["chat_id"]
	if !found {
		h.logger.Error(connCtx, "chat_id missing from select_chat payload map", "company", companyID, "agent", agentID, "user", userID)
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", "chat_id is missing.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for missing chat_id", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("chat_id missing from payload") // Return current sub and old chatID on error
	}

	chatID, ok := chatIDInterface.(string)
	if !ok || chatID == "" {
		h.logger.Error(connCtx, "Invalid chat_id type or empty in select_chat payload", "type_received", fmt.Sprintf("%T", chatIDInterface), "value", chatIDInterface, "company", companyID, "agent", agentID, "user", userID)
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", "chat_id must be a non-empty string.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for invalid chat_id type", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("invalid chat_id type or empty") // Return current sub and old chatID on error
	}

	h.logger.Info(connCtx, "Client selected chat", "chat_id", chatID, "company", companyID, "agent", agentID, "user", userID)

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
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for podID config error", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("podID is not configured") // Return current sub and old chatID on error
	}

	routeReg := h.connManager.RouteRegistrar()
	if routeReg == nil {
		h.logger.Error(connCtx, "RouteRegistry is not available in ConnectionManager. Cannot manage message routes.", "newChatID", chatID)
		// Optionally send an error back to the client
		errorResponse := domain.NewErrorResponse(domain.ErrInternal, "Server error", "Cannot process chat selection due to server error.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for RouteRegistry nil error", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("routeRegistry is nil") // Return current sub and old chatID on error
	}

	oldChatID := conn.GetCurrentChatID()

	if oldChatID == chatID {
		h.logger.Info(connCtx, "Client selected the same chat_id, no changes to routes or NATS subscription needed.", "chatID", chatID)
		return currentSpecificSub, chatID, nil // No change
	}

	// Unregister Old Message Route
	if oldChatID != "" {
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

	// Register New Message Route
	h.logger.Info(connCtx, "Registering new message route", "newChatID", chatID, "podID", podID, "ttl", routeTTL.String())
	if err := routeReg.RegisterMessageRoute(connCtx, companyID, agentID, chatID, podID, routeTTL); err != nil {
		h.logger.Error(connCtx, "Failed to register new message route",
			"newChatID", chatID, "podID", podID, "error", err.Error(),
		)
		errorResponse := domain.NewErrorResponse(domain.ErrInternal, "Failed to select chat", "Could not update message subscription.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for new route registration failure", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, oldChatID, fmt.Errorf("failed to register new message route: %w", err) // Return current sub and old chatID
	}
	h.logger.Info(connCtx, "Successfully registered new message route", "newChatID", chatID)

	// Manage NATS Subscription
	// 1. Drain general subscription if it exists
	if currentGeneralSub != nil && currentGeneralSub.IsValid() { // Added IsValid check
		h.logger.Info(connCtx, "Draining general NATS chats subscription as a specific chat is being selected.", "subject", currentGeneralSub.Subject())
		if err := currentGeneralSub.Drain(); err != nil {
			h.logger.Error(connCtx, "Failed to drain general NATS chats subscription", "subject", currentGeneralSub.Subject(), "error", err.Error())
			// Log and continue, attempt to subscribe to new one
		}
		// currentGeneralSub = nil // It will be nil-ed out by the caller if this function succeeds
	}

	// 2. Drain old specific subscription if it exists and is for a different chat
	if currentSpecificSub != nil && currentSpecificSub.IsValid() && currentSpecificSubChatID != "" && currentSpecificSubChatID != chatID { // Added IsValid check
		h.logger.Info(connCtx, "Draining previous NATS subscription for specific chat messages", "old_chat_id", currentSpecificSubChatID, "subject", currentSpecificSub.Subject())
		if err := currentSpecificSub.Drain(); err != nil {
			h.logger.Error(connCtx, "Failed to drain old specific NATS subscription", "old_chat_id", currentSpecificSubChatID, "subject", currentSpecificSub.Subject(), "error", err.Error())
			// Log and continue, attempt to subscribe to new one
		}
	}

	// 3. Subscribe to new chat message subject
	var newSpecificSubscription domain.NatsMessageSubscription // Changed type
	var newSubErr error
	if h.natsAdapter != nil {
		h.logger.Info(connCtx, "Subscribing to NATS for new chat_id", "companyID", companyID, "agentID", agentID, "new_chat_id", chatID)
		newSpecificSubscription, newSubErr = h.natsAdapter.SubscribeToChatMessages(connCtx, companyID, agentID, chatID, specificChatNatsMsgHandler)
		if newSubErr != nil {
			h.logger.Error(connCtx, "Failed to subscribe to NATS for new chat messages",
				"companyID", companyID, "agentID", agentID, "new_chat_id", chatID, "error", newSubErr.Error(),
			)
			errorResponse := domain.NewErrorResponse(domain.ErrSubscriptionFailure, "Could not subscribe to new chat events.", newSubErr.Error())
			if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
				h.logger.Error(connCtx, "Failed to send error to client for NATS sub failure", "error", sendErr.Error())
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeError)
			}
			conn.SetCurrentChatID(oldChatID) // Revert to old chat ID if new subscription fails
			return currentSpecificSub, oldChatID, fmt.Errorf("failed to subscribe to NATS for chat %s: %w", chatID, newSubErr)
		}
		h.logger.Info(connCtx, "Successfully subscribed to NATS for new chat messages", "new_chat_id", chatID, "subject", newSpecificSubscription.Subject())
	} else {
		h.logger.Warn(connCtx, "NATS adapter not available, cannot subscribe to new chat messages.", "new_chat_id", chatID)
	}

	conn.SetCurrentChatID(chatID)
	h.logger.Info(connCtx, "Updated current chat ID for connection", "newChatID", chatID)

	return newSpecificSubscription, chatID, nil
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
