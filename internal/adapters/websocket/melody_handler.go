package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/olahol/melody"
	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)

// sessionData stores connection-specific data
type sessionData struct {
	CompanyID     string
	AgentID       string
	UserID        string
	SessionKey    string
	CurrentChatID string
	NatsSub       *nats.Subscription
	mu            sync.Mutex
}

// MelodyHandler handles WebSocket connections using Melody library
type MelodyHandler struct {
	logger           domain.Logger
	configProvider   config.Provider
	connManager      *application.ConnectionManager
	natsAdapter      domain.NatsConsumer
	melody           *melody.Melody
	redisClient      *redis.Client
	messageForwarder domain.MessageForwarder
}

// NewMelodyHandler creates a new Melody-based WebSocket handler
func NewMelodyHandler(
	logger domain.Logger,
	cfgProvider config.Provider,
	connManager *application.ConnectionManager,
	natsAdapter domain.NatsConsumer,
	redisClient *redis.Client,
	messageForwarder domain.MessageForwarder,
) *MelodyHandler {
	// Create Melody instance with custom config
	m := melody.New()

	// Configure Melody with values from your config
	appCfg := cfgProvider.Get().App

	// Set Gorilla upgrader options
	m.Upgrader.CheckOrigin = func(r *http.Request) bool {
		// TODO: Add your origin check logic here
		return true // For now, accept all origins
	}

	// Set buffer sizes (melody uses gorilla websocket)
	m.Config.MaxMessageSize = 512000 // 512KB, adjust as needed
	m.Config.MessageBufferSize = appCfg.WebsocketMessageBufferSize
	if m.Config.MessageBufferSize <= 0 {
		m.Config.MessageBufferSize = 256
	}

	// Configure ping/pong based on your config
	m.Config.PongWait = time.Duration(appCfg.PongWaitSeconds) * time.Second
	m.Config.PingPeriod = time.Duration(appCfg.PingIntervalSeconds) * time.Second
	m.Config.WriteWait = time.Duration(appCfg.WriteTimeoutSeconds) * time.Second

	handler := &MelodyHandler{
		logger:           logger,
		configProvider:   cfgProvider,
		connManager:      connManager,
		natsAdapter:      natsAdapter,
		melody:           m,
		redisClient:      redisClient,
		messageForwarder: messageForwarder,
	}

	// Set up Melody event handlers
	handler.setupMelodyHandlers()

	// Start the one JetStream consumer for this pod
	// go handler.startJetStreamConsumer()

	return handler
}

// setupMelodyHandlers configures all Melody event callbacks
func (h *MelodyHandler) setupMelodyHandlers() {
	// Called when a new connection is established
	h.melody.HandleConnect(func(s *melody.Session) {
		data := h.getSessionData(s)
		if data == nil {
			h.logger.Error(context.Background(), "No session data in HandleConnect")
			s.Close()
			return
		}

		ctx := h.buildContext(s)
		h.logger.Info(ctx, "Melody: Connection established",
			"session_key", data.SessionKey,
			"company_id", data.CompanyID,
			"agent_id", data.AgentID,
			"user_id", data.UserID)

		// Send ready message
		readyMsg := domain.NewReadyMessage()
		if err := h.sendJSON(s, readyMsg); err != nil {
			h.logger.Error(ctx, "Failed to send ready message", "error", err.Error())
			s.Close()
			return
		}
		metrics.IncrementMessagesSent(domain.MessageTypeReady)

		// Restore chat selection from Redis if exists
		if h.redisClient != nil {
			chatSelectionKey := fmt.Sprintf("%s:selected_chat", data.SessionKey)
			if savedChatID, err := h.redisClient.Get(ctx, chatSelectionKey).Result(); err == nil && savedChatID != "" {
				data.mu.Lock()
				data.CurrentChatID = savedChatID
				data.mu.Unlock()
				h.logger.Info(ctx, "Restored chat selection", "chat_id", savedChatID)
			}
		}

		// Set up NATS subscription for this connection
		h.setupNatsSubscription(s, data)

		// Record initial activity
		if h.connManager != nil && h.connManager.SessionLocker() != nil {
			adaptiveCfg := h.configProvider.Get().AdaptiveTTL.SessionLock
			activityTTL := time.Duration(adaptiveCfg.MaxTTLSeconds) * time.Second
			if activityTTL <= 0 {
				activityTTL = time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second * 2
			}
			h.connManager.SessionLocker().RecordActivity(ctx, data.SessionKey, activityTTL)
		}

		// Register with global connection manager (for metrics and cleanup)
		if h.connManager != nil {
			melodyConn := &MelodyConnectionAdapter{session: s, handler: h}
			h.connManager.RegisterConnection(data.SessionKey, melodyConn, data.CompanyID, data.AgentID)
		}
	})

	// Called when a connection is closed
	h.melody.HandleDisconnect(func(s *melody.Session) {
		data := h.getSessionData(s)
		if data == nil {
			return
		}

		ctx := h.buildContext(s)
		h.logger.Info(ctx, "Melody: Connection closed",
			"session_key", data.SessionKey)

		// Clean up NATS subscription
		if data.NatsSub != nil && data.NatsSub.IsValid() {
			if err := data.NatsSub.Drain(); err != nil {
				h.logger.Error(ctx, "Error draining NATS subscription", "error", err.Error())
			}
		}

		// Deregister from connection manager
		if h.connManager != nil {
			h.connManager.DeregisterConnection(data.SessionKey)
		}

		metrics.DecrementActiveConnections()
	})

	// Called when a text message is received from client
	h.melody.HandleMessage(func(s *melody.Session, msg []byte) {
		data := h.getSessionData(s)
		if data == nil {
			return
		}

		ctx := h.buildContext(s)

		var baseMsg domain.BaseMessage
		if err := json.Unmarshal(msg, &baseMsg); err != nil {
			h.logger.Error(ctx, "Failed to unmarshal message", "error", err.Error())
			errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid message format", err.Error())
			h.sendJSON(s, domain.NewErrorMessage(errResp))
			metrics.IncrementMessagesReceived("invalid_json")
			return
		}

		metrics.IncrementMessagesReceived(baseMsg.Type)

		switch baseMsg.Type {
		case domain.MessageTypeSelectChat:
			h.handleSelectChatMessage(ctx, s, data, baseMsg.Payload)
		case domain.MessageTypeReady:
			// Echo ready message back
			h.sendJSON(s, baseMsg)
			metrics.IncrementMessagesSent(domain.MessageTypeReady)
		default:
			h.logger.Warn(ctx, "Unhandled message type", "type", baseMsg.Type)
			errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Unhandled message type", "Type: "+baseMsg.Type)
			h.sendJSON(s, domain.NewErrorMessage(errResp))
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
	})

	// Called when an error occurs
	h.melody.HandleError(func(s *melody.Session, err error) {
		ctx := h.buildContext(s)
		h.logger.Error(ctx, "Melody: WebSocket error", "error", err.Error())
	})
}

// ServeHTTP implements http.Handler interface
func (h *MelodyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get path parameters
	// pathCompany := r.PathValue("company")
	// pathAgent := r.PathValue("agent")

	// Get authenticated user context (from middleware)
	authCtx, ok := r.Context().Value(contextkeys.AuthUserContextKey).(*domain.AuthenticatedUserContext)
	if !ok || authCtx == nil {
		h.logger.Error(r.Context(), "No auth context found")
		errResp := domain.NewErrorResponse(
			domain.ErrInternal,
			"Authentication context missing",
			"Server configuration error",
		)
		errResp.WriteJSON(w, http.StatusInternalServerError)
		return
	}

	// Session lock acquisition
	lockCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	acquired, err := h.connManager.AcquireSessionLockOrNotify(lockCtx, authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	if err != nil {
		h.logger.Error(r.Context(), "Failed to acquire session lock", "error", err.Error())
		domain.NewErrorResponse(domain.ErrInternal, "Failed to process session", err.Error()).WriteJSON(w, http.StatusInternalServerError)
		return
	}
	if !acquired {
		h.logger.Warn(r.Context(), "Session lock not acquired (conflict)")
		metrics.IncrementSessionConflicts("user")
		domain.NewErrorResponse(domain.ErrSessionConflict, "Session already active elsewhere", "").WriteJSON(w, http.StatusConflict)
		return
	}

	sessionKey := rediskeys.SessionKey(authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	h.logger.Info(r.Context(), "Session lock acquired", "session_key", sessionKey)

	// Create session data
	sessionData := &sessionData{
		CompanyID:  authCtx.CompanyID,
		AgentID:    authCtx.AgentID,
		UserID:     authCtx.UserID,
		SessionKey: sessionKey,
	}

	// Store data in melody session Keys
	keys := map[string]interface{}{
		"session_data": sessionData,
		"request_id":   r.Context().Value(contextkeys.RequestIDKey),
	}

	metrics.IncrementConnectionsTotal()

	// Handle the WebSocket upgrade
	if err := h.melody.HandleRequestWithKeys(w, r, keys); err != nil {
		h.logger.Error(r.Context(), "Failed to handle WebSocket upgrade", "error", err.Error())
		// Release lock on failure
		if h.connManager != nil && h.connManager.SessionLocker() != nil {
			podID := h.configProvider.Get().Server.PodID
			h.connManager.SessionLocker().ReleaseLock(context.Background(), sessionKey, podID)
		}
	}
}

// Helper methods

func (h *MelodyHandler) getSessionData(s *melody.Session) *sessionData {
	if val, exists := s.Keys["session_data"]; exists {
		if data, ok := val.(*sessionData); ok {
			return data
		}
	}
	return nil
}

func (h *MelodyHandler) buildContext(s *melody.Session) context.Context {
	ctx := context.Background()

	// Add request ID if available
	if val, exists := s.Keys["request_id"]; exists {
		if reqID, ok := val.(string); ok {
			ctx = context.WithValue(ctx, contextkeys.RequestIDKey, reqID)
		}
	}

	// Add user context from session data
	if data := h.getSessionData(s); data != nil {
		ctx = context.WithValue(ctx, contextkeys.CompanyIDKey, data.CompanyID)
		ctx = context.WithValue(ctx, contextkeys.AgentIDKey, data.AgentID)
		ctx = context.WithValue(ctx, contextkeys.UserIDKey, data.UserID)
	}

	return ctx
}

func (h *MelodyHandler) sendJSON(s *melody.Session, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Write(data)
}

// setupNatsSubscription creates a regular NATS subscription for this connection
func (h *MelodyHandler) setupNatsSubscription(s *melody.Session, data *sessionData) {
	ctx := h.buildContext(s)

	// Subscribe to this agent's events using regular NATS (not JetStream)
	subject := fmt.Sprintf("websocket.%s.%s.>", data.CompanyID, data.AgentID)

	nc := h.natsAdapter.NatsConn()
	sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		// Handle incoming NATS message
		h.handleNatsMessage(s, data, msg)
	})

	if err != nil {
		h.logger.Error(ctx, "Failed to subscribe to NATS",
			"subject", subject,
			"error", err.Error())
		return
	}

	data.NatsSub = sub
	h.logger.Info(ctx, "NATS subscription created",
		"subject", subject,
		"session_key", data.SessionKey)
}

// handleNatsMessage processes messages from NATS
func (h *MelodyHandler) handleNatsMessage(s *melody.Session, data *sessionData, msg *nats.Msg) {
	ctx := h.buildContext(s)
	metrics.IncrementNatsMessagesReceived(msg.Subject)

	// Parse the subject to determine event type
	// websocket.{company}.{agent}.{eventType}[.{chatID}]
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		h.logger.Error(ctx, "Invalid NATS subject", "subject", msg.Subject)
		return
	}

	eventType := parts[3]

	// For message events, check if it matches current chat selection
	if eventType == "messages" && len(parts) >= 5 {
		chatID := parts[4]
		data.mu.Lock()
		currentChatID := data.CurrentChatID
		data.mu.Unlock()

		if currentChatID != chatID {
			// User hasn't selected this chat, skip
			return
		}
	}

	// Parse event payload
	var eventPayload domain.EnrichedEventPayload
	if err := json.Unmarshal(msg.Data, &eventPayload); err != nil {
		h.logger.Error(ctx, "Failed to unmarshal NATS message",
			"subject", msg.Subject,
			"error", err.Error())
		return
	}

	// Set event type if not already set
	if eventPayload.EventType == "" {
		switch eventType {
		case "chats":
			eventPayload.EventType = "chat"
		case "agents":
			eventPayload.EventType = "agent"
		case "messages":
			eventPayload.EventType = "message"
		default:
			eventPayload.EventType = eventType
		}
	}

	// Send to WebSocket client
	wsMessage := domain.NewEventMessage(eventPayload)
	if err := h.sendJSON(s, wsMessage); err != nil {
		h.logger.Error(ctx, "Failed to send message to client",
			"error", err.Error(),
			"session_key", data.SessionKey)
	} else {
		metrics.IncrementMessagesSent(domain.MessageTypeEvent)
	}
}

// handleSelectChatMessage handles chat selection
func (h *MelodyHandler) handleSelectChatMessage(ctx context.Context, s *melody.Session, data *sessionData, payload interface{}) {
	payloadMap, ok := payload.(map[string]interface{})
	if !ok {
		h.logger.Error(ctx, "Invalid select_chat payload structure")
		errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid payload structure", "Expected JSON object")
		h.sendJSON(s, domain.NewErrorMessage(errResp))
		metrics.IncrementMessagesSent(domain.MessageTypeError)
		return
	}

	chatIDInterface, found := payloadMap["chat_id"]
	if !found {
		h.logger.Error(ctx, "chat_id missing from payload")
		errResp := domain.NewErrorResponse(domain.ErrBadRequest, "chat_id is missing", "")
		h.sendJSON(s, domain.NewErrorMessage(errResp))
		metrics.IncrementMessagesSent(domain.MessageTypeError)
		return
	}

	chatID, ok := chatIDInterface.(string)
	if !ok || chatID == "" {
		h.logger.Error(ctx, "Invalid chat_id")
		errResp := domain.NewErrorResponse(domain.ErrBadRequest, "chat_id must be non-empty string", "")
		h.sendJSON(s, domain.NewErrorMessage(errResp))
		metrics.IncrementMessagesSent(domain.MessageTypeError)
		return
	}

	// Update current chat ID
	data.mu.Lock()
	oldChatID := data.CurrentChatID
	data.CurrentChatID = chatID
	data.mu.Unlock()

	h.logger.Info(ctx, "Chat selected",
		"chat_id", chatID,
		"old_chat_id", oldChatID,
		"session_key", data.SessionKey)

	// Persist to Redis
	if h.redisClient != nil {
		chatSelectionKey := fmt.Sprintf("%s:selected_chat", data.SessionKey)
		sessionTTL := time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second

		if err := h.redisClient.Set(ctx, chatSelectionKey, chatID, sessionTTL).Err(); err != nil {
			h.logger.Error(ctx, "Failed to persist chat selection", "error", err.Error())
		}
	}

	// Record activity
	if h.connManager != nil && h.connManager.SessionLocker() != nil {
		adaptiveCfg := h.configProvider.Get().AdaptiveTTL.SessionLock
		activityTTL := time.Duration(adaptiveCfg.MaxTTLSeconds) * time.Second
		if activityTTL <= 0 {
			activityTTL = time.Duration(h.configProvider.Get().App.SessionTTLSeconds) * time.Second * 2
		}
		h.connManager.SessionLocker().RecordActivity(ctx, data.SessionKey, activityTTL)
	}
}

// startJetStreamConsumer starts one JetStream consumer per pod that republishes to regular NATS
// func (h *MelodyHandler) startJetStreamConsumer() {
// 	ctx := context.Background()
// 	cfg := h.configProvider.Get()

// 	// Get JetStream context from NATS adapter
// 	// We need to type assert to the concrete type that has JetStreamContext method
// 	var js nats.JetStreamContext
// 	if adapter, ok := h.natsAdapter.(*nats.ConsumerAdapter); ok {
// 		js = adapter.JetStreamContext()
// 	} else {
// 		h.logger.Error(ctx, "NATS adapter doesn't support JetStream")
// 		return
// 	}

// 	// Subscribe to all websocket events with queue group
// 	sub, err := js.QueueSubscribe(
// 		"websocket.>",
// 		"ws-service-pods", // Queue group for load balancing
// 		func(msg *nats.Msg) {
// 			// Simply republish to regular NATS for fan-out
// 			nc := h.natsAdapter.NatsConn()
// 			if err := nc.Publish(msg.Subject, msg.Data); err != nil {
// 				h.logger.Error(ctx, "Failed to republish message",
// 					"subject", msg.Subject,
// 					"error", err.Error())
// 			}

// 			// ACK the JetStream message
// 			if err := msg.Ack(); err != nil {
// 				h.logger.Error(ctx, "Failed to ACK JetStream message",
// 					"subject", msg.Subject,
// 					"error", err.Error())
// 			}
// 		},
// 		nats.Durable("ws-melody-consumer"),
// 		nats.DeliverNew(),
// 		nats.ManualAck(),
// 		nats.AckWait(time.Duration(cfg.App.NatsAckWaitSeconds)*time.Second),
// 		nats.MaxAckPending(cfg.App.NATSMaxAckPending),
// 	)

// 	if err != nil {
// 		h.logger.Error(ctx, "Failed to start JetStream consumer", "error", err.Error())
// 		return
// 	}

// 	h.logger.Info(ctx, "JetStream consumer started",
// 		"subject", "websocket.>",
// 		"queue_group", "ws-service-pods")

// 	// Store subscription for cleanup if needed
// 	// You might want to add this to the handler struct
// 	_ = sub
// }

// Stop gracefully stops the Melody handler
func (h *MelodyHandler) Stop() error {
	h.logger.Info(context.Background(), "Stopping Melody handler...")
	return h.melody.Close()
}
