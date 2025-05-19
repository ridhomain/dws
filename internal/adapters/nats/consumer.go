package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// ConsumerAdapter handles connections and subscriptions to NATS JetStream.
type ConsumerAdapter struct {
	nc                *nats.Conn
	js                nats.JetStreamContext
	logger            domain.Logger
	cfg               *config.NATSConfig
	appName           string
	natsMaxAckPending int // Added to store this specific config value
}

// NewConsumerAdapter creates a new NATS ConsumerAdapter.
// It establishes a connection to the NATS server and gets a JetStream context.
func NewConsumerAdapter(ctx context.Context, cfgProvider config.Provider, appLogger domain.Logger) (*ConsumerAdapter, func(), error) {
	appFullCfg := cfgProvider.Get()
	natsCfg := appFullCfg.NATS
	appName := appFullCfg.App.ServiceName
	natsMaxAckPending := appFullCfg.App.NATSMaxAckPending // Get from AppConfig

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
		cfg:               &natsCfg,
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
		"stream_name", a.cfg.StreamName,
		"consumer_name", a.cfg.ConsumerName,
	)

	// Durable name for the consumer, incorporating company and agent to make it unique per subscription instance if needed,
	// or rely on NATS ephemeral consumer if durable name is complex to manage per websocket connection.
	// For a queue group, multiple subscribers can share a durable name, but often each subscriber instance
	// might want its own consumer state if not purely for load balancing. Given the task description suggests
	// "ws_fanout" as the group, it implies load balancing or shared consumption. Let's use a durable name based on group.
	// The PRD (FR-5) specifies a consumer `ws_fanout` for stream `wa_stream`.
	durableName := a.cfg.ConsumerName // From config, e.g., "ws_fanout_consumer"

	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		handler, // The message handler function passed in
		nats.Durable(durableName),
		nats.DeliverAll(),            // DeliverPolicy=All
		nats.ManualAck(),             // We will manually ack messages
		nats.AckWait(30*time.Second), // Example: Ack wait time, should be configurable
		// TODO: Add MaxAckPending from config (a.cfg.NATSMaxAckPending)
		// nats.MaxAckPending(a.cfg.NATSMaxAckPending) -> This config is for App, not NATSConfig directly.
		// It should be in appFullCfg.App.NATSMaxAckPending
		// For now, let's use a default or retrieve it correctly.
		nats.MaxAckPending(a.natsMaxAckPending), // Use the stored value
		// nats.MaxDeliver(), // Consider setting max redeliveries
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
		"stream_name", a.cfg.StreamName,
		"consumer_name", a.cfg.ConsumerName, // Assuming same consumer config base name
	)

	durableName := a.cfg.ConsumerName // Re-using the main consumer name for durability configuration.
	// If admin subscriptions need a different durable name strategy, this needs adjustment.

	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		handler,
		nats.Durable(durableName+"_admin_agents"), // Make durable name distinct for this type of subscription to avoid conflicts if same base consumer name is used.
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckWait(30*time.Second),            // TODO: Make configurable if different from main chats
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
