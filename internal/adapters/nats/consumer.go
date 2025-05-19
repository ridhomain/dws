package nats

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)

// ConsumerAdapter handles connections and subscriptions to NATS JetStream.
type ConsumerAdapter struct {
	nc                *nats.Conn
	js                nats.JetStreamContext
	logger            domain.Logger
	cfgProvider       config.Provider
	RouteRegistry     domain.RouteRegistry
	appName           string
	natsMaxAckPending int // Added to store this specific config value
}

// NewConsumerAdapter creates a new NATS ConsumerAdapter.
// It establishes a connection to the NATS server and gets a JetStream context.
func NewConsumerAdapter(ctx context.Context, cfgProvider config.Provider, appLogger domain.Logger, routeRegistry domain.RouteRegistry) (*ConsumerAdapter, func(), error) {
	appFullCfg := cfgProvider.Get()
	natsCfg := appFullCfg.NATS
	appName := appFullCfg.App.ServiceName
	natsMaxAckPending := appFullCfg.App.NATSMaxAckPending // Get from AppConfig
	natsAckWaitSeconds := appFullCfg.App.NatsAckWaitSeconds
	if natsAckWaitSeconds <= 0 {
		natsAckWaitSeconds = 30 // Default if not configured or invalid
		appLogger.Warn(ctx, "NatsAckWaitSeconds not configured or invalid, defaulting to 30s")
	}

	appLogger.Info(ctx, "Attempting to connect to NATS server", "url", natsCfg.URL)

	// TODO: Add more robust connection options from config (e.g., auth, TLS, timeouts)
	// For now, using a simple connection with a name.
	nc, err := nats.Connect(natsCfg.URL,
		nats.Name(fmt.Sprintf("%s-consumer-%s", appName, appFullCfg.Server.PodID)),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(5),
		nats.ReconnectWait(2*time.Second),
		nats.Timeout(5*time.Second), // Connection timeout
		nats.ErrorHandler(func(c *nats.Conn, s *nats.Subscription, err error) {
			appLogger.Error(ctx, "NATS error", "subscription", s.Subject, "error", err.Error())
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			appLogger.Info(ctx, "NATS connection closed")
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			appLogger.Info(ctx, "NATS reconnected", "url", c.ConnectedUrl())
		}),
		nats.DisconnectErrHandler(func(c *nats.Conn, err error) {
			appLogger.Warn(ctx, "NATS disconnected", "error", err)
		}),
	)
	if err != nil {
		appLogger.Error(ctx, "Failed to connect to NATS", "url", natsCfg.URL, "error", err.Error())
		return nil, nil, fmt.Errorf("failed to connect to NATS at %s: %w", natsCfg.URL, err)
	}

	appLogger.Info(ctx, "Successfully connected to NATS server", "url", nc.ConnectedUrl())

	js, err := nc.JetStream(nats.PublishAsyncMaxPending(256)) // Default, can be configured
	if err != nil {
		appLogger.Error(ctx, "Failed to get JetStream context", "error", err.Error())
		nc.Close()
		return nil, nil, fmt.Errorf("failed to get JetStream context: %w", err)
	}
	appLogger.Info(ctx, "Successfully obtained JetStream context")

	adapter := &ConsumerAdapter{
		nc:                nc,
		js:                js,
		logger:            appLogger,
		cfgProvider:       cfgProvider,
		RouteRegistry:     routeRegistry,
		appName:           appName,
		natsMaxAckPending: natsMaxAckPending, // Store it
	}

	cleanup := func() {
		appLogger.Info(context.Background(), "Closing NATS connection...")
		adapter.Close()
	}

	return adapter, cleanup, nil
}

// Close drains and closes the NATS connection.
func (a *ConsumerAdapter) Close() {
	if a.nc != nil && !a.nc.IsClosed() {
		a.logger.Info(context.Background(), "Draining NATS connection...")
		if err := a.nc.Drain(); err != nil {
			a.logger.Error(context.Background(), "Error draining NATS connection", "error", err.Error())
		} else {
			a.logger.Info(context.Background(), "NATS connection drained successfully.")
		}
		// Drain closes the connection, so an explicit Close() might be redundant or error if already closed.
		// nats.Conn.Drain() "will close the connection after the drain is complete".
	}
}

// JetStreamContext returns the JetStream context.
func (a *ConsumerAdapter) JetStreamContext() nats.JetStreamContext {
	return a.js
}

// NatsConn returns the underlying NATS connection.
func (a *ConsumerAdapter) NatsConn() *nats.Conn {
	return a.nc
}

// SubscribeToChats subscribes to the chat events for a specific company and agent.
// It uses QueueSubscribe with DeliverAllPolicy and ManualAckPolicy.
// The provided nats.MsgHandler will be called for each received message.
func (a *ConsumerAdapter) SubscribeToChats(ctx context.Context, companyID, agentID string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}

	subject := fmt.Sprintf("wa.%s.%s.chats", companyID, agentID)
	queueGroup := "ws_fanout" // As per task description

	a.logger.Info(ctx, "Attempting to subscribe to NATS subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"stream_name", a.cfgProvider.Get().NATS.StreamName,
		"consumer_name", a.cfgProvider.Get().NATS.ConsumerName,
	)

	// Durable name for the consumer, incorporating company and agent to make it unique per subscription instance if needed,
	// or rely on NATS ephemeral consumer if durable name is complex to manage per websocket connection.
	// For a queue group, multiple subscribers can share a durable name, but often each subscriber instance
	// might want its own consumer state if not purely for load balancing. Given the task description suggests
	// "ws_fanout" as the group, it implies load balancing or shared consumption. Let's use a durable name based on group.
	// The PRD (FR-5) specifies a consumer `ws_fanout` for stream `wa_stream`.
	durableName := a.cfgProvider.Get().NATS.ConsumerName // From config, e.g., "ws_fanout_consumer"
	ackWait := time.Duration(a.cfgProvider.Get().App.NatsAckWaitSeconds) * time.Second
	if ackWait <= 0 {
		ackWait = 30 * time.Second // Fallback default
	}

	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		handler, // The message handler function passed in
		nats.Durable(durableName),
		nats.DeliverAll(), // DeliverPolicy=All
		nats.ManualAck(),  // We will manually ack messages
		nats.AckWait(ackWait),
		nats.MaxAckPending(a.natsMaxAckPending), // Use the stored value
	)

	if err != nil {
		a.logger.Error(ctx, "Failed to subscribe to NATS subject",
			"subject", subject,
			"queue_group", queueGroup,
			"durable_name", durableName,
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to subscribe to NATS subject %s: %w", subject, err)
	}

	a.logger.Info(ctx, "Successfully subscribed to NATS subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"durable_name", durableName,
	)

	return sub, nil
}

// SubscribeToChatMessages subscribes to specific chat message subjects (e.g., wa.<company>.<agent>.messages.<chat_id>).
// The provided handler is responsible for processing messages, including ownership checks.
func (a *ConsumerAdapter) SubscribeToChatMessages(ctx context.Context, companyID, agentID, chatID string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}

	subject := rediskeys.RouteKeyMessages(companyID, agentID, chatID) // This generates "route:..." which is not a NATS subject
	// Correct NATS subject format:
	subject = fmt.Sprintf("wa.%s.%s.messages.%s", companyID, agentID, chatID)

	// Use the same queue group and consumer name as SubscribeToChats for now,
	// as these messages are part of the overall fanout strategy.
	queueGroup := "ws_fanout"
	durableName := a.cfgProvider.Get().NATS.ConsumerName // ws_fanout_consumer or similar
	ackWaitMessages := time.Duration(a.cfgProvider.Get().App.NatsAckWaitSeconds) * time.Second
	if ackWaitMessages <= 0 {
		ackWaitMessages = 30 * time.Second // Fallback default
	}

	a.logger.Info(ctx, "Attempting to subscribe to NATS chat messages subject",
		"subject", subject,
		"queue_group", queueGroup,
		"durable_name", durableName,
	)

	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		handler,
		nats.Durable(durableName+"_messages"), // Ensure durable name is unique per type of subscription if needed or managed carefully
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckWait(ackWaitMessages),
		nats.MaxAckPending(a.natsMaxAckPending),
	)

	if err != nil {
		a.logger.Error(ctx, "Failed to subscribe to NATS chat messages subject",
			"subject", subject,
			"queue_group", queueGroup,
			"durable_name", durableName+"_messages",
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to subscribe to NATS chat messages subject %s: %w", subject, err)
	}

	a.logger.Info(ctx, "Successfully subscribed to NATS chat messages subject",
		"subject", subject,
		"queue_group", queueGroup,
		"durable_name", durableName+"_messages",
	)
	return sub, nil
}

// Helper function to parse NATS subject for message streams
// Example subject: wa.comp1.agentA.messages.chatXYZ
func ParseNATSMessageSubject(subject string) (companyID, agentID, chatID string, err error) {
	parts := strings.Split(subject, ".")
	// Expected: "wa", "<companyID>", "<agentID>", "messages", "<chatID>"
	if len(parts) != 5 || parts[0] != "wa" || parts[3] != "messages" {
		err = fmt.Errorf("invalid NATS message subject format: %s", subject)
		return
	}
	companyID = parts[1]
	agentID = parts[2]
	chatID = parts[4]
	if companyID == "" || agentID == "" || chatID == "" {
		err = fmt.Errorf("empty companyID, agentID, or chatID in NATS subject: %s", subject)
		return
	}
	return
}

// SubscribeToAgentEvents subscribes to the agent events for a specific company and agent pattern.
// It uses QueueSubscribe with DeliverAllPolicy and ManualAckPolicy.
// The provided nats.MsgHandler will be called for each received message.
func (a *ConsumerAdapter) SubscribeToAgentEvents(ctx context.Context, companyIDPattern, agentIDPattern string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}
	// Subject pattern: wa.<companyIDPattern>.<agentIDPattern>.agents
	subject := fmt.Sprintf("wa.%s.%s.agents", companyIDPattern, agentIDPattern)
	queueGroup := "ws_fanout_admin" // Potentially a different queue group for admin, or reuse existing if appropriate.
	// For now, using a distinct queue group to isolate admin agent event consumption if needed.
	// If it should share the same pool as user chat events, this can be changed to "ws_fanout".
	// The PRD states "existing JetStream consumer logic (e.g., ws_fanout consumer configuration adapted...)"
	// This implies we might reuse `ws_fanout` or use a similar config. Let's stick to `ws_fanout` to align with that.
	queueGroup = "ws_fanout"

	a.logger.Info(ctx, "Attempting to subscribe to NATS agent events subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"stream_name", a.cfgProvider.Get().NATS.StreamName,
		"consumer_name", a.cfgProvider.Get().NATS.ConsumerName, // Assuming same consumer config base name
	)

	durableName := a.cfgProvider.Get().NATS.ConsumerName // Re-using the main consumer name for durability configuration.
	// If admin subscriptions need a different durable name strategy, this needs adjustment.
	ackWaitAdmin := time.Duration(a.cfgProvider.Get().App.NatsAckWaitSeconds) * time.Second
	if ackWaitAdmin <= 0 {
		ackWaitAdmin = 30 * time.Second // Fallback default
	}

	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		handler,
		nats.Durable(durableName+"_admin_agents"), // Make durable name distinct for this type of subscription to avoid conflicts if same base consumer name is used.
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckWait(ackWaitAdmin),
		nats.MaxAckPending(a.natsMaxAckPending), // Reuse existing config for MaxAckPending
	)

	if err != nil {
		a.logger.Error(ctx, "Failed to subscribe to NATS agent events subject",
			"subject", subject,
			"queue_group", queueGroup,
			"durable_name", durableName+"_admin_agents",
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to subscribe to NATS agent events subject %s: %w", subject, err)
	}

	a.logger.Info(ctx, "Successfully subscribed to NATS agent events subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"durable_name", durableName+"_admin_agents",
	)
	return sub, nil
}

// TODO: Implement logic for Subtask 6.3 (Parse and Forward EnrichedEventPayload)
// This will involve creating a message handler function that uses the domain.Connection
// to write messages to the WebSocket client.
