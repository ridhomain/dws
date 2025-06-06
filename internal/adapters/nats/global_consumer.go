package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
)

// GlobalConsumerHandler handles all NATS messages for this WebSocket service instance
type GlobalConsumerHandler struct {
	logger         domain.Logger
	configProvider config.Provider
	connRegistry   *LocalConnectionRegistry
	subscription   *nats.Subscription
	js             nats.JetStreamContext
	mu             sync.Mutex
}

// LocalConnectionRegistry maintains connections indexed by company and agent
type LocalConnectionRegistry struct {
	// company -> agent -> sessionKey -> connection
	connections map[string]map[string]map[string]domain.ManagedConnection
	// sessionKey -> company/agent mapping for quick lookup during deregistration
	sessionMapping   map[string]connectionInfo
	adminConnections map[string]adminConnection
	mu               sync.RWMutex
}

type adminConnection struct {
	conn                domain.ManagedConnection
	subscribedCompanyID string // "*" or specific company
	subscribedAgentID   string // "*" or specific agent
}

type connectionInfo struct {
	companyID string
	agentID   string
}

// NewGlobalConsumerHandler creates a new global consumer handler
func NewGlobalConsumerHandler(
	logger domain.Logger,
	configProvider config.Provider,
	js nats.JetStreamContext,
) *GlobalConsumerHandler {
	return &GlobalConsumerHandler{
		logger:         logger,
		configProvider: configProvider,
		connRegistry:   NewLocalConnectionRegistry(),
		js:             js,
	}
}

// NewLocalConnectionRegistry creates a new connection registry
func NewLocalConnectionRegistry() *LocalConnectionRegistry {
	return &LocalConnectionRegistry{
		connections:    make(map[string]map[string]map[string]domain.ManagedConnection),
		sessionMapping: make(map[string]connectionInfo),
	}
}

// Start begins the global consumer subscription
func (h *GlobalConsumerHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.subscription != nil {
		return fmt.Errorf("global consumer already started")
	}

	cfg := h.configProvider.Get()
	queueGroup := "ws-service-group"

	// Subscribe to all websocket.* events with queue group for load balancing
	sub, err := h.js.QueueSubscribe(
		"websocket.>", // Subscribe to all wa events
		queueGroup,    // Queue group for load balancing across replicas
		h.handleMessage,
		nats.Durable("ws-global-consumer"),
		nats.DeliverNew(), // Only new messages, no replay
		nats.ManualAck(),  // Manual acknowledgment
		nats.AckWait(time.Duration(cfg.App.NatsAckWaitSeconds)*time.Second),
		nats.MaxAckPending(cfg.App.NATSMaxAckPending),
	)

	if err != nil {
		h.logger.Error(ctx, "Failed to start global NATS consumer", "error", err.Error())
		return fmt.Errorf("failed to subscribe to NATS: %w", err)
	}

	h.subscription = sub
	h.logger.Info(ctx, "Global NATS consumer started successfully",
		"subject", "websocket.>",
		"queue_group", queueGroup,
		"durable_name", "ws-global-consumer")

	return nil
}

// Stop gracefully stops the global consumer
func (h *GlobalConsumerHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.subscription == nil {
		return nil
	}

	h.logger.Info(context.Background(), "Stopping global NATS consumer...")

	if err := h.subscription.Drain(); err != nil {
		h.logger.Error(context.Background(), "Error draining NATS subscription", "error", err.Error())
		return err
	}

	h.subscription = nil
	h.logger.Info(context.Background(), "Global NATS consumer stopped")
	return nil
}

// handleMessage processes incoming NATS messages
func (h *GlobalConsumerHandler) handleMessage(msg *nats.Msg) {
	startTime := time.Now()
	metrics.IncrementNatsMessagesReceived(msg.Subject)

	// Create context with request ID
	ctx := context.Background()
	if reqID := msg.Header.Get("X-Request-ID"); reqID != "" {
		ctx = context.WithValue(ctx, contextkeys.RequestIDKey, reqID)
	}

	h.logger.Debug(ctx, "Global consumer received message",
		"subject", msg.Subject,
		"data_size", len(msg.Data))

	// Parse subject to determine routing
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		h.logger.Error(ctx, "Invalid subject format", "subject", msg.Subject)
		msg.Ack() // ACK invalid messages to prevent redelivery
		return
	}

	// websocket.{company}.{agent}.{eventType}[.{additional}]
	companyID := parts[1]
	agentID := parts[2]
	eventType := parts[3]

	// Get relevant connections for this company/agent
	connections := h.connRegistry.GetConnections(companyID, agentID)

	if eventType == "agents" {
		adminConns := h.getAdminConnectionsForAgentEvent(companyID, agentID)
		// Merge admin connections into the broadcast list
		for sessionKey, conn := range adminConns {
			connections[sessionKey] = conn
		}
	}

	if len(connections) == 0 {
		// No local connections for this company/agent, ACK and skip
		h.logger.Debug(ctx, "No local connections for company/agent, skipping",
			"company", companyID,
			"agent", agentID,
			"subject", msg.Subject)
		msg.Ack()
		return
	}

	h.logger.Info(ctx, "Broadcasting message to local connections",
		"company", companyID,
		"agent", agentID,
		"event_type", eventType,
		"connection_count", len(connections))

	// Parse event payload
	var eventPayload domain.EnrichedEventPayload
	if err := json.Unmarshal(msg.Data, &eventPayload); err != nil {
		h.logger.Error(ctx, "Failed to unmarshal event payload",
			"subject", msg.Subject,
			"error", err.Error())
		msg.Ack() // ACK to prevent redelivery of malformed messages
		return
	}

	// Set event type based on subject
	switch eventType {
	case "chats":
		eventPayload.EventType = "chat"
	case "agents":
		eventPayload.EventType = "agent"
	case "messages":
		eventPayload.EventType = "message"
		// For messages, we need to check if the connection has selected this chat
		if len(parts) >= 5 {
			chatID := parts[4]
			connections = h.filterConnectionsByChat(connections, chatID)
		}
	case "contacts":
		eventPayload.EventType = "contact"
	default:
		eventPayload.EventType = eventType
	}

	// Broadcast to all relevant connections
	successCount := 0
	failCount := 0

	for sessionKey, conn := range connections {
		// Check if connection context is still valid
		if conn.Context().Err() != nil {
			h.logger.Debug(ctx, "Skipping closed connection", "session_key", sessionKey)
			continue
		}

		// TODO: Add assigned_to filtering here for non-admin users
		// This will be implemented based on the token's admin status

		wsMessage := domain.NewEventMessage(eventPayload)
		if err := conn.WriteJSON(wsMessage); err != nil {
			h.logger.Error(ctx, "Failed to write message to WebSocket",
				"session_key", sessionKey,
				"error", err.Error())
			failCount++
		} else {
			successCount++
			metrics.IncrementMessagesSent(domain.MessageTypeEvent)
		}
	}

	h.logger.Info(ctx, "Message broadcast completed",
		"subject", msg.Subject,
		"success_count", successCount,
		"fail_count", failCount,
		"duration_ms", time.Since(startTime).Milliseconds())

	// ACK the message after processing
	if err := msg.Ack(); err != nil {
		h.logger.Error(ctx, "Failed to ACK message", "subject", msg.Subject, "error", err.Error())
	}
}

// filterConnectionsByChat filters connections that have selected the specific chat
func (h *GlobalConsumerHandler) filterConnectionsByChat(connections map[string]domain.ManagedConnection, chatID string) map[string]domain.ManagedConnection {
	filtered := make(map[string]domain.ManagedConnection)

	for sessionKey, conn := range connections {
		if conn.GetCurrentChatID() == chatID {
			filtered[sessionKey] = conn
		}
	}

	return filtered
}

// RegisterConnection adds a connection to the registry
func (h *GlobalConsumerHandler) RegisterConnection(sessionKey, companyID, agentID string, conn domain.ManagedConnection) {
	h.connRegistry.mu.Lock()
	defer h.connRegistry.mu.Unlock()

	// Check if this is an admin connection (empty company/agent IDs)
	if companyID == "" && agentID == "" {
		// This is an admin connection
		// For now, we'll store it in a special "admin" company/agent
		if h.connRegistry.connections["_admin"] == nil {
			h.connRegistry.connections["_admin"] = make(map[string]map[string]domain.ManagedConnection)
		}
		if h.connRegistry.connections["_admin"]["_admin"] == nil {
			h.connRegistry.connections["_admin"]["_admin"] = make(map[string]domain.ManagedConnection)
		}

		h.connRegistry.connections["_admin"]["_admin"][sessionKey] = conn

		// Note: We'll need to parse the sessionKey to get admin info for filtering
		// sessionKey format: "session:admin:{adminID}"

		h.logger.Info(context.Background(), "Admin connection registered in global consumer",
			"session_key", sessionKey)
		return
	}

	// Ensure company map exists
	if h.connRegistry.connections[companyID] == nil {
		h.connRegistry.connections[companyID] = make(map[string]map[string]domain.ManagedConnection)
	}

	// Ensure agent map exists
	if h.connRegistry.connections[companyID][agentID] == nil {
		h.connRegistry.connections[companyID][agentID] = make(map[string]domain.ManagedConnection)
	}

	// Add connection
	h.connRegistry.connections[companyID][agentID][sessionKey] = conn

	// Store mapping for easy deregistration
	h.connRegistry.sessionMapping[sessionKey] = connectionInfo{
		companyID: companyID,
		agentID:   agentID,
	}

	h.logger.Info(context.Background(), "Connection registered in global consumer",
		"session_key", sessionKey,
		"company", companyID,
		"agent", agentID)
}

// DeregisterConnection removes a connection from the registry
func (h *GlobalConsumerHandler) DeregisterConnection(sessionKey string) {
	h.connRegistry.mu.Lock()
	defer h.connRegistry.mu.Unlock()

	// Get connection info
	info, exists := h.connRegistry.sessionMapping[sessionKey]
	if !exists {
		h.logger.Warn(context.Background(), "Attempted to deregister unknown connection",
			"session_key", sessionKey)
		return
	}

	// Remove from connections map
	if companyConns, ok := h.connRegistry.connections[info.companyID]; ok {
		if agentConns, ok := companyConns[info.agentID]; ok {
			delete(agentConns, sessionKey)

			// Clean up empty maps
			if len(agentConns) == 0 {
				delete(companyConns, info.agentID)
			}
			if len(companyConns) == 0 {
				delete(h.connRegistry.connections, info.companyID)
			}
		}
	}

	// Remove from session mapping
	delete(h.connRegistry.sessionMapping, sessionKey)

	h.logger.Info(context.Background(), "Connection deregistered from global consumer",
		"session_key", sessionKey,
		"company", info.companyID,
		"agent", info.agentID)
}

// GetConnections returns all connections for a company/agent
func (r *LocalConnectionRegistry) GetConnections(companyID, agentID string) map[string]domain.ManagedConnection {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]domain.ManagedConnection)

	if companyConns, ok := r.connections[companyID]; ok {
		if agentConns, ok := companyConns[agentID]; ok {
			// Return a copy to avoid concurrent modification
			for k, v := range agentConns {
				result[k] = v
			}
		}
	}

	return result
}

func (h *GlobalConsumerHandler) getAdminConnectionsForAgentEvent(companyID, agentID string) map[string]domain.ManagedConnection {
	h.connRegistry.mu.RLock()
	defer h.connRegistry.mu.RUnlock()

	result := make(map[string]domain.ManagedConnection)

	for sessionKey, adminConn := range h.connRegistry.adminConnections {
		// Check if admin subscription pattern matches
		companyMatch := adminConn.subscribedCompanyID == "*" || adminConn.subscribedCompanyID == companyID
		agentMatch := adminConn.subscribedAgentID == "*" || adminConn.subscribedAgentID == agentID

		if companyMatch && agentMatch {
			result[sessionKey] = adminConn.conn
		}
	}

	return result
}

// GetStats returns statistics about the connection registry
func (h *GlobalConsumerHandler) GetStats() map[string]interface{} {
	h.connRegistry.mu.RLock()
	defer h.connRegistry.mu.RUnlock()

	totalConnections := 0
	companyCount := len(h.connRegistry.connections)

	for _, agents := range h.connRegistry.connections {
		for _, conns := range agents {
			totalConnections += len(conns)
		}
	}

	return map[string]interface{}{
		"total_connections": totalConnections,
		"company_count":     companyCount,
		"session_count":     len(h.connRegistry.sessionMapping),
	}
}
