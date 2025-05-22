package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"

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
	// Debug log attempt to publish kill message
	a.logger.Debug(ctx, "Preparing to publish session kill message",
		"channel", channel,
		"new_pod_id", message.NewPodID,
		"operation", "PublishSessionKill")

	payloadBytes, errMarshal := json.Marshal(message)
	if errMarshal != nil {
		a.logger.Error(ctx, "Failed to marshal KillSwitchMessage for publishing", "channel", channel, "error", errMarshal.Error())
		return fmt.Errorf("failed to marshal KillSwitchMessage: %w", errMarshal)
	}

	// Debug log the actual payload that will be sent
	a.logger.Debug(ctx, "Publishing session kill message with payload",
		"channel", channel,
		"new_pod_id", message.NewPodID,
		"payload", string(payloadBytes),
		"operation", "PublishSessionKill")

	// Publish message to Redis with retries
	var publishAttemptErr error
	var receiverCount int64
	maxRetries := 3
	retryDelay := 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		// Check context before attempting publish, especially in a retry loop
		select {
		case <-ctx.Done():
			a.logger.Error(ctx, "Context cancelled before publishing session kill message", "channel", channel, "error", ctx.Err())
			return ctx.Err()
		default:
		}

		result := a.redisClient.Publish(ctx, channel, string(payloadBytes))
		receiverCount, publishAttemptErr = result.Result()
		if publishAttemptErr == nil {
			break // Success
		}
		a.logger.Warn(ctx, "Failed to publish session kill message, retrying...",
			"channel", channel, "attempt", i+1, "max_attempts", maxRetries, "error", publishAttemptErr.Error())
		if i < maxRetries-1 {
			select {
			case <-time.After(retryDelay):
				// continue to next retry
			case <-ctx.Done():
				a.logger.Error(ctx, "Context cancelled during publish retry wait for session kill message", "channel", channel, "error", ctx.Err())
				return ctx.Err() // Return context error
			}
			retryDelay *= 2 // Exponential backoff for subsequent retries
		}
	}

	if publishAttemptErr != nil {
		a.logger.Error(ctx, "Failed to publish session kill message to Redis after multiple retries", "channel", channel, "error", publishAttemptErr.Error())
		return fmt.Errorf("failed to publish to Redis channel '%s' after %d retries: %w", channel, maxRetries, publishAttemptErr)
	}

	// Debug log publish success with receiver count
	a.logger.Debug(ctx, "Session kill message publish result",
		"channel", channel,
		"new_pod_id", message.NewPodID,
		"receiver_count", receiverCount,
		"operation", "PublishSessionKill")

	a.logger.Info(ctx, "Successfully published session kill message", "channel", channel, "new_pod_id", message.NewPodID, "receiver_count", receiverCount)
	return nil
}

// SubscribeToSessionKillPattern subscribes to a Redis channel pattern (e.g., "session_kill:*")
// and invokes the handler for each message. This function will start a goroutine to persistently
// manage the subscription and will return nil if the initial setup for the goroutine is successful.
// The goroutine will attempt to maintain the subscription until the provided context is cancelled.
func (a *KillSwitchPubSubAdapter) SubscribeToSessionKillPattern(ctx context.Context, pattern string, handler domain.KillSwitchMessageHandler) error {
	a.logger.Info(ctx, "Initiating persistent subscription routine for Redis pattern", "pattern", pattern)

	// Basic check to prevent multiple goroutines from the same adapter instance if called more than once.
	// This is a simple guard; a more robust solution might involve a sync.Once or state tracking.
	if a.sub != nil {
		a.logger.Warn(ctx, "Subscription attempt on an adapter that may already have an active subscription goroutine", "pattern", pattern)
		// Depending on desired behavior, could return an error or allow, assuming context management handles lifecycle.
		// For now, let it proceed, but log warning. The old code returned an error.
		// return fmt.Errorf("subscription goroutine may already be active for this adapter instance")
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				a.logger.Error(context.Background(), "Panic recovered in persistent Redis PubSub routine",
					"pattern", pattern, "panic_info", fmt.Sprintf("%v", r), "stacktrace", string(debug.Stack()))
			}
			// Ensure subscription is closed if this goroutine exits.
			// Use a background context for logging here as the original ctx might be done.
			if a.sub != nil {
				a.logger.Info(context.Background(), "Closing PubSub subscription from defer in persistent routine", "pattern", pattern)
				if err := a.sub.Close(); err != nil {
					a.logger.Error(context.Background(), "Error closing Redis subscription in defer", "pattern", pattern, "error", err)
				}
				a.sub = nil
			}
			a.logger.Info(context.Background(), "Persistent subscription routine for Redis pattern has exited", "pattern", pattern)
		}()

		initialRetryDelay := 2 * time.Second // Start with a shorter delay
		maxRetryDelay := 30 * time.Second    // Max delay between retries
		currentRetryDelay := initialRetryDelay

		for {
			// Check for context cancellation at the beginning of each attempt cycle.
			select {
			case <-ctx.Done():
				a.logger.Info(ctx, "Context cancelled, stopping persistent subscription attempts.", "pattern", pattern)
				return
			default:
				// Continue to attempt subscription
			}

			a.logger.Info(ctx, "Attempting to establish Redis PSubscribe", "pattern", pattern, "current_retry_delay_if_needed", currentRetryDelay.String())

			// Create a new PubSub object for this attempt.
			// Pass the main context 'ctx' which governs the overall lifetime.
			psCtx := a.redisClient.PSubscribe(ctx, pattern)

			// Atomically store the pubsub object. This is important for the Close() method.
			// However, direct assignment to a.sub here before confirmation can be tricky if Close() is called concurrently.
			// A better approach might be to only set a.sub once confirmed, and Close() uses a channel to signal this goroutine.
			// For now, let's keep it simpler: assign, then confirm. Close() will close whatever a.sub points to.

			_, err := psCtx.Receive(ctx) // This waits for the subscription confirmation.
			if err != nil {
				a.logger.Error(ctx, "Failed to establish or confirm Redis PSubscribe", "pattern", pattern, "error", err, "next_retry_in", currentRetryDelay.String())
				if psCtx != nil {
					_ = psCtx.Close() // Close the PubSub object from this failed attempt.
				}

				// Wait for the retry delay or context cancellation.
				select {
				case <-time.After(currentRetryDelay):
					newDelay := currentRetryDelay * 2
					if newDelay > maxRetryDelay {
						currentRetryDelay = maxRetryDelay
					} else {
						currentRetryDelay = newDelay
					}
					continue // Retry PSubscribe
				case <-ctx.Done():
					a.logger.Info(ctx, "Context cancelled during PSubscribe retry wait", "pattern", pattern)
					return
				}
			}

			// Subscription successful
			a.logger.Info(ctx, "Successfully subscribed to Redis pattern, entering message processing loop", "pattern", pattern)
			a.sub = psCtx                         // Now store the confirmed, active subscription.
			currentRetryDelay = initialRetryDelay // Reset retry delay on successful subscription.

			msgChan := a.sub.Channel()
			processingMessages := true
			for processingMessages {
				select {
				case msg, ok := <-msgChan:
					if !ok {
						a.logger.Warn(ctx, "Redis pub/sub message channel closed. Will attempt to resubscribe.", "pattern", pattern)
						processingMessages = false // Exit this inner loop to trigger resubscription by the outer loop.
						// Don't 'break' here, let the loop condition handle exit.
						continue // Ensure we go to the top of the select for the next iteration if processingMessages is still true (it won't be).
					}

					a.logger.Debug(ctx, "Received message on Redis subscription",
						"channel", msg.Channel, "pattern", msg.Pattern, "payload", msg.Payload)

					var killMsg domain.KillSwitchMessage
					if errUnmarshal := json.Unmarshal([]byte(msg.Payload), &killMsg); errUnmarshal != nil {
						a.logger.Error(ctx, "Failed to unmarshal KillSwitchMessage from pub/sub",
							"channel", msg.Channel, "payload", msg.Payload, "error", errUnmarshal.Error())
						continue // Skip malformed messages
					}

					a.logger.Info(ctx, "Received session kill message", "channel", msg.Channel, "new_pod_id", killMsg.NewPodID)
					// Run the handler in a separate goroutine to avoid blocking the message loop.
					// This is important if the handler can take time or perform blocking operations.
					// However, handlers for kill messages are expected to be quick (closing a local connection).
					// For now, direct call. If handler becomes complex, reconsider safego.Execute here.
					if errHandler := handler(msg.Channel, killMsg); errHandler != nil {
						a.logger.Error(ctx, "Error in KillSwitchMessageHandler",
							"channel", msg.Channel, "new_pod_id", killMsg.NewPodID, "error", errHandler.Error())
					}

				case <-ctx.Done():
					a.logger.Info(ctx, "Context cancelled (during message processing). Stopping Redis message processor and subscription routine.", "pattern", pattern)
					processingMessages = false // Exit inner loop.
					// The main defer in this goroutine will handle a.sub.Close() if a.sub is not nil.
					return // Exit the main goroutine.
				}
			} // End of message processing (inner) loop

			// If we exited the inner loop because msgChan closed, a.sub might still be the old one.
			// It's important to nil it out before the outer loop tries to PSubscribe again,
			// and ensure it's closed.
			if a.sub != nil {
				a.logger.Info(ctx, "Closing current PubSub subscription object before attempting to resubscribe", "pattern", pattern)
				if errClose := a.sub.Close(); errClose != nil {
					a.logger.Error(ctx, "Error closing pubsub before resubscribe", "pattern", pattern, "error", errClose)
				}
				a.sub = nil
			}

			// Small pause before the outer loop retries PSubscribe, to prevent rapid spinning if Redis is down.
			// This is in addition to currentRetryDelay used when PSubscribe itself fails.
			// This handles the case where the channel closes cleanly but we want to retry.
			select {
			case <-time.After(initialRetryDelay / 2): // A small, fixed delay.
			case <-ctx.Done():
				a.logger.Info(ctx, "Context cancelled during brief pause before resubscription attempt", "pattern", pattern)
				return
			}
		} // End of main (outer) retry loop
	}() // End of the main goroutine for persistent subscription

	return nil // Return immediately, indicating the goroutine has been started.
}

// Close closes the Redis PubSub subscription if one is active.
// It signals the subscription goroutine to terminate by closing the underlying PubSub object.
func (a *KillSwitchPubSubAdapter) Close() error {
	a.logger.Info(context.Background(), "Close called on KillSwitchPubSubAdapter")
	if a.sub != nil {
		// Closing a.sub will cause its message channel (a.sub.Channel()) to close.
		// The message processing loop within SubscribeToSessionKillPattern will detect this,
		// exit its inner loop, and then the outer loop will check ctx.Done().
		// If the context passed to SubscribeToSessionKillPattern is also being cancelled as part of shutdown,
		// the goroutine will terminate.
		a.logger.Info(context.Background(), "Attempting to close active Redis pub/sub subscription object.")
		err := a.sub.Close()
		// Set a.sub to nil regardless of close error to prevent reuse by a new Subscribe call
		// if the goroutine hasn't fully exited and cleaned it up itself yet.
		// This makes Close idempotent from the perspective of a.sub.
		a.sub = nil
		if err != nil {
			a.logger.Error(context.Background(), "Error closing Redis pub/sub subscription via adapter's Close method", "error", err.Error())
			return fmt.Errorf("error closing Redis pub/sub: %w", err)
		}
		a.logger.Info(context.Background(), "Redis pub/sub subscription object closed via adapter's Close method.")
		return nil
	}
	a.logger.Info(context.Background(), "No active Redis pub/sub subscription object to close in adapter.")
	return nil // Or fmt.Errorf("no active subscription to close") if stricter error needed
}
