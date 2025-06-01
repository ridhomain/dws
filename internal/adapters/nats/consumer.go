package nats

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// natsSubscriptionWrapper wraps nats.Subscription to implement domain.NatsMessageSubscription.
// This allows the domain layer to remain independent of the concrete NATS library types.
type natsSubscriptionWrapper struct {
	*nats.Subscription
}

// Drain calls Drain on the underlying nats.Subscription.
func (nsw *natsSubscriptionWrapper) Drain() error {
	return nsw.Subscription.Drain()
}

// IsValid calls IsValid on the underlying nats.Subscription.
func (nsw *natsSubscriptionWrapper) IsValid() bool {
	return nsw.Subscription.IsValid()
}

// Subject calls Subject on the underlying nats.Subscription.
func (nsw *natsSubscriptionWrapper) Subject() string {
	return nsw.Subscription.Subject
}

// ConsumerAdapter handles connections and subscriptions to NATS JetStream.
type ConsumerAdapter struct {
	nc                *nats.Conn
	js                nats.JetStreamContext
	logger            domain.Logger
	cfgProvider       config.Provider
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
	natsAckWaitSeconds := appFullCfg.App.NatsAckWaitSeconds
	if natsAckWaitSeconds <= 0 {
		natsAckWaitSeconds = 30 // Default if not configured or invalid
		appLogger.Warn(ctx, "NatsAckWaitSeconds not configured or invalid, defaulting to 30s")
	}

	appLogger.Info(ctx, "Attempting to connect to NATS server", "url", natsCfg.URL)

	// Build NATS connection options from config
	natsOptions := []nats.Option{
		nats.Name(fmt.Sprintf("%s-consumer-%s", appName, appFullCfg.Server.PodID)),
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
	}

	if natsCfg.RetryOnFailedConnect {
		natsOptions = append(natsOptions, nats.RetryOnFailedConnect(true))
	} else {
		// If explicitly set to false, you might want nats.NoReconnect() or ensure RetryOnFailedConnect(false) is effective.
		// For now, if true, we add it. NATS default is true anyway.
	}

	if natsCfg.MaxReconnects != 0 { // NATS default for MaxReconnects is 60 if RetryOnFailedConnect is true. 0 might mean use default, -1 infinite.
		natsOptions = append(natsOptions, nats.MaxReconnects(natsCfg.MaxReconnects))
	}
	if natsCfg.ReconnectWaitSeconds > 0 {
		natsOptions = append(natsOptions, nats.ReconnectWait(time.Duration(natsCfg.ReconnectWaitSeconds)*time.Second))
	}
	if natsCfg.ConnectTimeoutSeconds > 0 {
		natsOptions = append(natsOptions, nats.Timeout(time.Duration(natsCfg.ConnectTimeoutSeconds)*time.Second))
	}
	if natsCfg.PingIntervalSeconds > 0 {
		natsOptions = append(natsOptions, nats.PingInterval(time.Duration(natsCfg.PingIntervalSeconds)*time.Second))
	}
	if natsCfg.MaxPingsOut > 0 {
		natsOptions = append(natsOptions, nats.MaxPingsOutstanding(natsCfg.MaxPingsOut))
	}

	nc, err := nats.Connect(natsCfg.URL, natsOptions...)
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
func (a *ConsumerAdapter) SubscribeToChats(ctx context.Context, companyID, agentID string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}

	// Ephemeral subscriptions
	// Use a queue group that is unique per company and agent to avoid conflicts
	baseConsumerName := a.cfgProvider.Get().NATS.ConsumerName
	queueGroup := fmt.Sprintf("%s_%s_%s", baseConsumerName, companyID, agentID) // Unique per company and agent
	subject := fmt.Sprintf("websocket.%s.%s.chats", companyID, agentID)

	a.logger.Info(ctx, "Attempting to subscribe to NATS subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"stream_name", a.cfgProvider.Get().NATS.StreamName,
		"consumer_name", a.cfgProvider.Get().NATS.ConsumerName,
	)
	ackWait := time.Duration(a.cfgProvider.Get().App.NatsAckWaitSeconds) * time.Second
	if ackWait <= 0 {
		ackWait = 30 * time.Second // Fallback default
	}

	natsHandler := nats.MsgHandler(handler) // Convert domain.NatsMessageHandler to nats.MsgHandler

	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		natsHandler, // The message handler function passed in
		nats.DeliverNew(),
		nats.ManualAck(), // We will manually ack messages
		nats.AckWait(ackWait),
		nats.MaxAckPending(a.natsMaxAckPending), // Use the stored value
	)

	if err != nil {
		a.logger.Error(ctx, "Failed to subscribe to NATS subject",
			"subject", subject,
			"queue_group", queueGroup,
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to subscribe to NATS subject %s: %w", subject, err)
	}

	a.logger.Info(ctx, "Successfully subscribed to NATS subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
	)

	return &natsSubscriptionWrapper{Subscription: sub}, nil
}

// SubscribeToChatMessages subscribes to specific chat message subjects (e.g., websocket.<company>.<agent>.messages.<chat_id>).
// The provided handler is responsible for processing messages, including ownership checks.
func (a *ConsumerAdapter) SubscribeToChatMessages(ctx context.Context, companyID, agentID, chatID string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}

	subject := fmt.Sprintf("websocket.%s.%s.messages.%s", companyID, agentID, chatID)

	// Ephemeral subscriptions
	// Use a distinct queue group for specific chat messages
	baseConsumerName := a.cfgProvider.Get().NATS.ConsumerName
	queueGroup := fmt.Sprintf("%s_%s_%s_%s_messages_q", baseConsumerName, companyID, agentID, chatID)

	ackWaitMessages := time.Duration(a.cfgProvider.Get().App.NatsAckWaitSeconds) * time.Second
	if ackWaitMessages <= 0 {
		ackWaitMessages = 30 * time.Second // Fallback default
	}

	a.logger.Info(ctx, "Attempting to subscribe to NATS chat messages subject",
		"subject", subject,
		"queue_group", queueGroup,
	)

	natsHandler := nats.MsgHandler(handler) // Convert domain.NatsMessageHandler to nats.MsgHandler

	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		natsHandler,
		nats.DeliverNew(),
		nats.ManualAck(),
		nats.AckWait(ackWaitMessages),
		nats.MaxAckPending(a.natsMaxAckPending),
	)

	if err != nil {
		a.logger.Error(ctx, "Failed to subscribe to NATS chat messages subject",
			"subject", subject,
			"queue_group", queueGroup,
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to subscribe to NATS chat messages subject %s: %w", subject, err)
	}

	a.logger.Info(ctx, "Successfully subscribed to NATS chat messages subject",
		"subject", subject,
		"queue_group", queueGroup,
	)
	return &natsSubscriptionWrapper{Subscription: sub}, nil
}

// Helper function to parse NATS subject for message streams
// Example subject: websocket.comp1.agentA.messages.chatXYZ
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
func (a *ConsumerAdapter) SubscribeToAgentEvents(ctx context.Context, companyIDPattern, agentIDPattern string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}
	// Subject pattern: websocket.<companyIDPattern>.<agentIDPattern>.agents
	subject := fmt.Sprintf("websocket.%s.%s.agents", companyIDPattern, agentIDPattern)
	queueGroup := "ws_fanout_admin_events"

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

	natsHandler := nats.MsgHandler(handler) // Convert domain.NatsMessageHandler to nats.MsgHandler

	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		natsHandler,
		nats.Durable(durableName+"_admin_agents"), // Make durable name distinct for this type of subscription to avoid conflicts if same base consumer name is used.
		nats.DeliverNew(), // Only deliver new messages, don't replay old ones
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
	return &natsSubscriptionWrapper{Subscription: sub}, nil
}
