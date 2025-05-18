package redis

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// KillSwitchPubSubAdapter implements both KillSwitchPublisher and KillSwitchSubscriber using Redis.
type KillSwitchPubSubAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
	sub         *redis.PubSub // Holds the active subscription
}

// NewKillSwitchPubSubAdapter creates a new adapter for Redis pub/sub.
func NewKillSwitchPubSubAdapter(redisClient *redis.Client, logger domain.Logger) *KillSwitchPubSubAdapter {
	return &KillSwitchPubSubAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}

// PublishSessionKill publishes a message to the specified Redis channel.
func (a *KillSwitchPubSubAdapter) PublishSessionKill(ctx context.Context, channel string, message domain.KillSwitchMessage) error {
	payloadBytes, err := json.Marshal(message)
	if err != nil {
		a.logger.Error(ctx, "Failed to marshal KillSwitchMessage for publishing", "channel", channel, "error", err.Error())
		return fmt.Errorf("failed to marshal KillSwitchMessage: %w", err)
	}

	err = a.redisClient.Publish(ctx, channel, string(payloadBytes)).Err()
	if err != nil {
		a.logger.Error(ctx, "Failed to publish session kill message to Redis", "channel", channel, "error", err.Error())
		return fmt.Errorf("failed to publish to Redis channel '%s': %w", channel, err)
	}
	a.logger.Info(ctx, "Successfully published session kill message", "channel", channel, "new_pod_id", message.NewPodID)
	return nil
}

// SubscribeToSessionKillPattern subscribes to a Redis channel pattern (e.g., "session_kill:*")
// and invokes the handler for each message. This is a blocking call and should typically be run in a goroutine.
func (a *KillSwitchPubSubAdapter) SubscribeToSessionKillPattern(ctx context.Context, pattern string, handler domain.KillSwitchMessageHandler) error {
	if a.sub != nil {
		// Prevent multiple subscriptions on the same adapter instance for simplicity,
		// though Redis client itself can handle multiple subscriptions.
		return fmt.Errorf("already subscribed or subscription active on this adapter instance")
	}

	a.sub = a.redisClient.PSubscribe(ctx, pattern)
	// Importantly, Receive() must be called to confirm the subscription and initiate message flow.
	// However, we should not block here indefinitely if the context is cancelled or if there's an immediate error.
	// A common pattern is to check the first message or error from Receive() to confirm subscription success.
	// Then, the message loop is handled by iterating over a.sub.Channel().
	// For robustness, one might wrap the Receive() in a select with ctx.Done().

	// Try to receive the first message to confirm subscription is active.
	// This can be a PSubscribe confirmation message or an actual message.
	_, err := a.sub.Receive(ctx)
	if err != nil {
		a.logger.Error(ctx, "Failed to confirm Redis PSubscribe", "pattern", pattern, "error", err.Error())
		// Ensure subscription is cleaned up if confirmation fails
		_ = a.sub.Close()
		a.sub = nil
		return fmt.Errorf("failed to subscribe to pattern '%s': %w", pattern, err)
	}
	a.logger.Info(ctx, "Successfully subscribed to Redis pattern", "pattern", pattern)

	ch := a.sub.Channel() // Get the message channel

	go func() {
		for msg := range ch {
			var killMsg domain.KillSwitchMessage
			if errUnmarshal := json.Unmarshal([]byte(msg.Payload), &killMsg); errUnmarshal != nil {
				a.logger.Error(ctx, "Failed to unmarshal KillSwitchMessage from pub/sub",
					"channel", msg.Channel,
					"payload", msg.Payload,
					"error", errUnmarshal.Error(),
				)
				continue // Skip malformed messages
			}

			a.logger.Info(ctx, "Received session kill message", "channel", msg.Channel, "new_pod_id", killMsg.NewPodID)
			if errHandler := handler(msg.Channel, killMsg); errHandler != nil {
				a.logger.Error(ctx, "Error in KillSwitchMessageHandler",
					"channel", msg.Channel,
					"new_pod_id", killMsg.NewPodID,
					"error", errHandler.Error(),
				)
				// Decide on error handling: continue, retry, or stop subscription?
				// For now, just log and continue.
			}
		}
		// If the loop exits, it means the subscription channel was closed.
		a.logger.Info(ctx, "Subscription goroutine ended for pattern", "pattern", pattern)
	}()

	return nil // The subscription itself runs in a goroutine; this function returns after setup.
}

// Close closes the Redis PubSub subscription.
func (a *KillSwitchPubSubAdapter) Close() error {
	if a.sub != nil {
		err := a.sub.Close()
		a.sub = nil // Clear the stored subscription
		if err != nil {
			a.logger.Error(context.Background(), "Error closing Redis pub/sub subscription", "error", err.Error())
			return fmt.Errorf("error closing Redis pub/sub: %w", err)
		}
		a.logger.Info(context.Background(), "Redis pub/sub subscription closed.")
		return nil
	}
	return fmt.Errorf("no active subscription to close")
}
