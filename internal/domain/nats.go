package domain

import (
	"context"

	"github.com/nats-io/nats.go"
)

// NatsMessageSubscription represents an active NATS subscription.
// It's a wrapper around nats.Subscription to abstract concrete types if needed later,
// though for now it directly exposes nats.Subscription methods used.
type NatsMessageSubscription interface {
	Drain() error
	IsValid() bool
	Subject() string
	// Add other nats.Subscription methods if they become necessary for domain/application logic
}

// NatsMessageHandler is the type for functions that process NATS messages.
type NatsMessageHandler func(msg *nats.Msg)

// NatsConsumer defines the interface for interacting with a NATS message consumer.
// This abstraction allows for different NATS client implementations or mocking for tests.
type NatsConsumer interface {
	// SubscribeToChats subscribes to general chat events for a company and agent.
	SubscribeToChats(ctx context.Context, companyID, agentID string, handler NatsMessageHandler) (NatsMessageSubscription, error)

	// SubscribeToChatMessages subscribes to messages for a specific chat thread.
	SubscribeToChatMessages(ctx context.Context, companyID, agentID, chatID string, handler NatsMessageHandler) (NatsMessageSubscription, error)

	// SubscribeToAgentEvents subscribes to agent table events, typically for admin users.
	// companyIDPattern and agentIDPattern can use NATS wildcards (e.g., "*", ">").
	SubscribeToAgentEvents(ctx context.Context, companyIDPattern, agentIDPattern string, handler NatsMessageHandler) (NatsMessageSubscription, error)

	// NatsConn returns the underlying NATS connection, primarily for health checks or specific low-level operations.
	// Use with caution, prefer specific interface methods where possible.
	NatsConn() *nats.Conn

	// Close gracefully closes the NATS consumer connection.
	Close()
}
