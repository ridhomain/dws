package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
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

	// gRPC related imports
	"github.com/google/uuid"                                                               // Added for request_id generation
	dws_message_fwd "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc/proto" // Alias for your generated proto package
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"                 // For XRequestIDHeader
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"         // Added for health check
	"google.golang.org/grpc/credentials/insecure" // For now, will add mTLS later
	"google.golang.org/grpc/metadata"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// Handler handles WebSocket connection upgrades and subsequent communication.
type Handler struct {
	logger         domain.Logger
	configProvider config.Provider
	connManager    *application.ConnectionManager
	natsAdapter    *appnats.ConsumerAdapter
	grpcClientPool *sync.Map // Map targetAddress (string) to *grpc.ClientConn
	// Future dependencies: connectionManager domain.ConnectionManager
}

// NewHandler creates a new WebSocket Handler.
func NewHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter *appnats.ConsumerAdapter) *Handler {
	return &Handler{
		logger:         logger,
		configProvider: cfgProvider,
		connManager:    connManager,
		natsAdapter:    natsAdapter,
		grpcClientPool: &sync.Map{},
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
		duration := time.Since(startTime).Seconds()
		metrics.ObserveConnectionDuration(duration)
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

	readyMessage := domain.NewReadyMessage()
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to client", "error", err.Error())
		return
	}
	metrics.IncrementMessagesSent(domain.MessageTypeReady)
	h.logger.Info(connCtx, "Sent 'ready' message to client")

	// NATS Subscription management
	var generalNatsSubscription *nats.Subscription
	var specificNatsSubscription *nats.Subscription // Renamed from currentNatsSubscription
	var currentSpecificChatID string                // Renamed from currentSubscriptionChatID

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
			_ = msg.Ack()
			return
		}
		wsMessage := domain.NewEventMessage(eventPayload)
		if errWrite := conn.WriteJSON(wsMessage); errWrite != nil {
			h.logger.Error(msgCtx, "Failed to forward general chat event to WebSocket client", "subject", msg.Subject, "event_id", eventPayload.EventID, "error", errWrite.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeEvent)
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
			h.logger.Info(connCtx, "Successfully subscribed to general NATS chats topic", "subject", generalNatsSubscription.Subject)
		}
	} else {
		h.logger.Warn(connCtx, "NATS adapter not available, cannot subscribe to general chat events.")
	}

	// Renamed specificChatNatsMessageHandler from natsMessageHandler for clarity
	specificChatNatsMessageHandler := func(msg *nats.Msg) {
		metrics.IncrementNatsMessagesReceived(msg.Subject) // Increment NATS received metric

		// Start: request_id handling for NATS message
		natsRequestID := msg.Header.Get(middleware.XRequestIDHeader) // Using const from middleware package
		if natsRequestID == "" {
			natsRequestID = uuid.NewString()
			h.logger.Debug(connCtx, "Generated new request_id for NATS message", "subject", msg.Subject, "new_request_id", natsRequestID)
		} else {
			h.logger.Debug(connCtx, "Using existing request_id from NATS message header", "subject", msg.Subject, "request_id", natsRequestID)
		}
		msgCtx := context.WithValue(connCtx, contextkeys.RequestIDKey, natsRequestID)
		// End: request_id handling for NATS message

		msgCompanyID, msgAgentID, msgChatID, err := appnats.ParseNATSMessageSubject(msg.Subject)
		if err != nil {
			h.logger.Error(msgCtx, "Failed to parse NATS message subject", "subject", msg.Subject, "error", err.Error())
			_ = msg.Ack() // Ack to prevent redelivery of malformed subjects
			return
		}

		currentPodID := h.configProvider.Get().Server.PodID
		if currentPodID == "" {
			h.logger.Error(connCtx, "Current PodID is not configured, cannot determine message ownership.", "subject", msg.Subject)
			_ = msg.Ack() // Ack as we can't process further
			return
		}

		// Check ownership using RouteRegistry from NATS adapter
		// This check needs to be against the chatID from the NATS message subject itself.
		ownerPodID, err := h.natsAdapter.RouteRegistry.GetOwningPodForMessageRoute(connCtx, msgCompanyID, msgAgentID, msgChatID) // Correctly using exported field
		if err != nil {
			if errors.Is(err, appredis.ErrNoOwningPod) { // Correctly using imported package for error
				h.logger.Warn(connCtx, "No owning pod found for message route in Redis, potential race or cleanup issue. NACKing message.", "subject", msg.Subject, "chat_id_from_subject", msgChatID)
				// FR-8A: NACK the message if no owning pod is found to prevent message loss.
				// NATS will attempt redelivery or send to a dead-letter queue if configured.
				if nakErr := msg.Nak(); nakErr != nil {
					h.logger.Error(connCtx, "Failed to NACK NATS message for ErrNoOwningPod", "subject", msg.Subject, "error", nakErr.Error())
				}
				return // Stop processing this message
			} else {
				h.logger.Error(connCtx, "Failed to get owning pod for message route from Redis", "subject", msg.Subject, "error", err.Error())
				_ = msg.Ack() // Ack as we can't determine ownership, to prevent blocking the consumer on this message.
				return
			}
		}

		// If we reach here, err is nil, and ownerPodID is the ID of the owning pod.
		// It cannot be empty if a route was found, because GetOwningPodForMessageRoute returns members[0].
		// If no route was found, ErrNoOwningPod would have been returned and handled above.

		var isOwner bool
		if ownerPodID == currentPodID {
			isOwner = true
		} else {
			// If ownerPodID is not currentPodID, it implies another specific pod owns it.
			// ownerPodID should not be empty here due to the logic in GetOwningPodForMessageRoute
			// and the ErrNoOwningPod handling above.
			isOwner = false
			if ownerPodID == "" {
				// This case is defensive and should ideally not be reached if GetOwningPodForMessageRoute behaves as expected (returning error for no owner).
				h.logger.Error(connCtx, "Internal logic inconsistency: ownerPodID is empty after GetOwningPodForMessageRoute succeeded. Assuming not owner.", "subject", msg.Subject)
			}
		}

		if isOwner {
			// Subtask 8.2: Implement Local Message Delivery for Owner Pod
			h.logger.Info(msgCtx, "Current pod IS THE OWNER of the message route. Delivering locally.", "subject", msg.Subject, "podID", currentPodID)
			var eventPayload domain.EnrichedEventPayload
			if errUnmarshal := json.Unmarshal(msg.Data, &eventPayload); errUnmarshal != nil {
				h.logger.Error(msgCtx, "Failed to unmarshal NATS message into EnrichedEventPayload (owner)",
					"subject", msg.Subject, "error", errUnmarshal.Error(), "raw_data", string(msg.Data))
				_ = msg.Ack()
				return
			}
			wsMessage := domain.NewEventMessage(eventPayload)
			if errWrite := conn.WriteJSON(wsMessage); errWrite != nil {
				h.logger.Error(msgCtx, "Failed to forward NATS message to WebSocket client (owner)",
					"subject", msg.Subject, "event_id", eventPayload.EventID, "error", errWrite.Error(),
				)
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeEvent) // NATS event forwarded to client
			}
		} else {
			// Subtask 8.3: Forward Messages via gRPC to Owner Pod(s) When Not Owner
			h.logger.Info(msgCtx, "Current pod IS NOT THE OWNER of the message route. Attempting gRPC hop.",
				"subject", msg.Subject, "current_pod_id", currentPodID, "owner_pod_id", ownerPodID)

			if ownerPodID != "" { // Ensure there is a specific owner pod to forward to
				gprcTargetAddress := fmt.Sprintf("%s:%d", ownerPodID, h.configProvider.Get().Server.GRPCPort)
				h.logger.Info(msgCtx, "Attempting to forward message via gRPC", "target_address", gprcTargetAddress)

				var grpcConn *grpc.ClientConn
				var errClient error
				var connFromPool bool

				if connVal, okPool := h.grpcClientPool.Load(gprcTargetAddress); okPool {
					grpcConn, connFromPool = connVal.(*grpc.ClientConn)
					if !connFromPool {
						h.logger.Error(msgCtx, "Invalid type in gRPC client pool, removing entry.", "target_address", gprcTargetAddress, "type", fmt.Sprintf("%T", connVal))
						h.grpcClientPool.Delete(gprcTargetAddress)
						grpcConn = nil
					} else {
						// Basic health check for pooled connection
						connState := grpcConn.GetState()
						if connState != connectivity.Ready && connState != connectivity.Idle {
							h.logger.Warn(msgCtx, "Pooled gRPC connection is not Ready or Idle, discarding.", "target_address", gprcTargetAddress, "state", connState.String())
							h.grpcClientPool.Delete(gprcTargetAddress)
							grpcConn.Close()     // Close the unhealthy connection
							grpcConn = nil       // Force creation of a new connection
							connFromPool = false // No longer considered from pool for error handling later if new one fails
						} else {
							h.logger.Debug(msgCtx, "Reusing gRPC client connection from pool", "target_address", gprcTargetAddress, "state", connState.String())
						}
					}
				}

				if grpcConn == nil { // If not found in pool, type assertion failed, or explicitly nilled due to bad type
					h.logger.Info(msgCtx, "Creating new gRPC client connection", "target_address", gprcTargetAddress)
					connOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
					newlyCreatedConn, newErrClient := grpc.NewClient(gprcTargetAddress, connOpts...)
					if newErrClient == nil {
						grpcConn = newlyCreatedConn                         // Use the newly created connection
						h.grpcClientPool.Store(gprcTargetAddress, grpcConn) // Store the new connection
					} else {
						errClient = newErrClient // Store the error to be handled below
					}
				}

				if errClient != nil { // This error is from grpc.NewClient if pool retrieval failed and new connection also failed
					h.logger.Error(msgCtx, "Failed to establish gRPC connection to owner pod",
						"target_pod", ownerPodID, "address", gprcTargetAddress, "error", errClient.Error())
				} else if grpcConn != nil { // If we have a connection (either from pool or newly created)
					// defer grpcConn.Close() // DO NOT CLOSE HERE - it's pooled. Lifecycle managed elsewhere (e.g. app shutdown or eviction strategy)
					client := dws_message_fwd.NewMessageForwardingServiceClient(grpcConn)

					var domainPayload domain.EnrichedEventPayload
					if errUnmarshal := json.Unmarshal(msg.Data, &domainPayload); errUnmarshal != nil {
						h.logger.Error(msgCtx, "Failed to unmarshal NATS message data for gRPC forwarding", "subject", msg.Subject, "error", errUnmarshal.Error())
					} else {
						protoData, errProtoStruct := structpb.NewStruct(domainPayload.Data.(map[string]interface{}))
						if errProtoStruct != nil {
							h.logger.Error(msgCtx, "Failed to convert domainPayload.Data to proto.Struct for gRPC", "error", errProtoStruct.Error())
						} else {
							grpcRequest := &dws_message_fwd.PushEventRequest{
								Payload: &dws_message_fwd.EnrichedEventPayloadMessage{
									EventId:   domainPayload.EventID,
									EventType: domainPayload.EventType,
									Timestamp: timestamppb.New(domainPayload.Timestamp),
									Source:    domainPayload.Source,
									Data:      protoData,
								},
								TargetCompanyId: msgCompanyID,
								TargetAgentId:   msgAgentID,
								TargetChatId:    msgChatID,
								SourcePodId:     currentPodID,
							}

							md := metadata.New(nil)
							if reqID, okCtxVal := msgCtx.Value(contextkeys.RequestIDKey).(string); okCtxVal && reqID != "" {
								md.Set(string(contextkeys.RequestIDKey), reqID)
							}
							pushCtxWithMetadata := metadata.NewOutgoingContext(msgCtx, md)

							grpcClientTimeoutSeconds := h.configProvider.Get().App.GRPCCLientForwardTimeoutSeconds
							grpcClientTimeout := 5 * time.Second
							if grpcClientTimeoutSeconds > 0 {
								grpcClientTimeout = time.Duration(grpcClientTimeoutSeconds) * time.Second
							}

							pushCtx, pushCancel := context.WithTimeout(pushCtxWithMetadata, grpcClientTimeout)
							resp, errPush := client.PushEvent(pushCtx, grpcRequest)
							pushCancel()

							if errPush != nil {
								h.logger.Warn(msgCtx, "gRPC PushEvent to owner pod failed", "target_pod", ownerPodID, "address", gprcTargetAddress, "error", errPush.Error(), "is_pooled_conn", connFromPool)
								// If a pooled connection fails, remove it from the pool so a new one is tried next time.
								if connFromPool {
									h.grpcClientPool.Delete(gprcTargetAddress)
									grpcConn.Close() // Close the problematic connection
									h.logger.Info(msgCtx, "Removed and closed failed gRPC connection from pool", "target_address", gprcTargetAddress)
								}
								// Retry logic is removed for now to simplify. Can be added back if needed.
							} else if resp != nil && !resp.Success {
								h.logger.Warn(msgCtx, "gRPC PushEvent to owner pod was not successful", "target_pod", ownerPodID, "response_message", resp.Message, "is_pooled_conn", connFromPool)
							} else if resp != nil && resp.Success {
								h.logger.Info(msgCtx, "Successfully forwarded message via gRPC", "target_pod", ownerPodID, "event_id", domainPayload.EventID, "is_pooled_conn", connFromPool)
								metrics.IncrementGrpcMessagesSent(ownerPodID)
							}
						}
					}
				}
			} else {
				h.logger.Warn(msgCtx, "No specific owner pod ID found for gRPC hop, message will not be forwarded.", "subject", msg.Subject)
			}
		}

		if ackErr := msg.Ack(); ackErr != nil {
			h.logger.Error(msgCtx, "Failed to ACK NATS message after processing", "subject", msg.Subject, "error", ackErr.Error())
		}
	}

	// Defer cleanup for all subscriptions
	defer func() {
		if generalNatsSubscription != nil {
			h.logger.Info(connCtx, "Draining general NATS subscription on connection close", "subject", generalNatsSubscription.Subject)
			if unsubErr := generalNatsSubscription.Drain(); unsubErr != nil {
				h.logger.Error(connCtx, "Error draining general NATS subscription on close", "subject", generalNatsSubscription.Subject, "error", unsubErr.Error())
			}
		}
		if specificNatsSubscription != nil {
			h.logger.Info(connCtx, "Draining specific NATS subscription on connection close", "subject", specificNatsSubscription.Subject, "chatID", currentSpecificChatID)
			if unsubErr := specificNatsSubscription.Drain(); unsubErr != nil {
				h.logger.Error(connCtx, "Error draining specific NATS subscription on close", "subject", specificNatsSubscription.Subject, "error", unsubErr.Error())
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
					pingWriteCtx, pingCancel := context.WithTimeout(connCtx, writeTimeout)
					if err := conn.Ping(pingWriteCtx); err != nil {
						h.logger.Error(connCtx, "Failed to send ping", "error", err.Error())
						pingCancel()
						conn.Close(websocket.StatusAbnormalClosure, "Ping failure")
						return
					}
					pingCancel()
					h.logger.Debug(connCtx, "Sent ping")

					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr(), "lastPong", conn.LastPongTime())
						conn.Close(websocket.StatusPolicyViolation, "Pong timeout")
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
				newSub, newChatID, err := h.handleSelectChatMessage(connCtx, conn, p, companyID, agentID, userID, baseMsg.Payload, specificChatNatsMessageHandler, generalNatsSubscription, specificNatsSubscription, currentSpecificChatID)
				if err != nil {
					h.logger.Error(connCtx, "Error handling select_chat message", "error", err.Error())
					errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to process chat selection", err.Error())
					if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
						h.logger.Error(connCtx, "Failed to send error to client for select_chat failure", "error", sendErr.Error())
					} else {
						metrics.IncrementMessagesSent(domain.MessageTypeError)
					}
				} else {
					// If handleSelectChatMessage was successful, generalNatsSubscription might have been cleared if it existed.
					// And specificNatsSubscription would be the new one.
					generalNatsSubscription = nil // Explicitly nil out general if specific is now active
					specificNatsSubscription = newSub
					currentSpecificChatID = newChatID
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
	rawPayload []byte,
	companyID, agentID, userID string,
	payloadData interface{},
	specificChatNatsMsgHandler nats.MsgHandler, // Renamed for clarity
	currentGeneralSub *nats.Subscription, // Pass general subscription
	currentSpecificSub *nats.Subscription, // Pass current specific subscription
	currentSpecificSubChatID string, // Pass current specific chat ID
) (*nats.Subscription, string, error) { // Returns new specific subscription, new chatID, and error

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
	if currentGeneralSub != nil {
		h.logger.Info(connCtx, "Draining general NATS chats subscription as a specific chat is being selected.", "subject", currentGeneralSub.Subject)
		if err := currentGeneralSub.Drain(); err != nil {
			h.logger.Error(connCtx, "Failed to drain general NATS chats subscription", "subject", currentGeneralSub.Subject, "error", err.Error())
			// Log and continue, attempt to subscribe to new one
		}
		// currentGeneralSub = nil // It will be nil-ed out by the caller if this function succeeds
	}

	// 2. Drain old specific subscription if it exists and is for a different chat
	if currentSpecificSub != nil && currentSpecificSubChatID != "" && currentSpecificSubChatID != chatID {
		h.logger.Info(connCtx, "Draining previous NATS subscription for specific chat messages", "old_chat_id", currentSpecificSubChatID, "subject", currentSpecificSub.Subject)
		if err := currentSpecificSub.Drain(); err != nil {
			h.logger.Error(connCtx, "Failed to drain old specific NATS subscription", "old_chat_id", currentSpecificSubChatID, "subject", currentSpecificSub.Subject, "error", err.Error())
			// Log and continue, attempt to subscribe to new one
		}
	}

	// 3. Subscribe to new chat message subject
	var newSpecificSubscription *nats.Subscription
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
		h.logger.Info(connCtx, "Successfully subscribed to NATS for new chat messages", "new_chat_id", chatID, "subject", newSpecificSubscription.Subject)
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
