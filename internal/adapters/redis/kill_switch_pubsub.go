package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// KillSwitchPubSubAdapter implements both KillSwitchPublisher and KillSwitchSubscriber using Redis.
type KillSwitchPubSubAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
	sub         *redis.PubSub      // Holds the active subscription
	subMutex    sync.Mutex         // Protects access to sub field
	wg          sync.WaitGroup     // Tracks active subscription goroutines
	cancelCtx   context.CancelFunc // Cancels subscription goroutines
	ctx         context.Context    // Context for subscription goroutines
}

// NewKillSwitchPubSubAdapter creates a new adapter for Redis pub/sub.
func NewKillSwitchPubSubAdapter(redisClient *redis.Client, logger domain.Logger) *KillSwitchPubSubAdapter {
	ctx, cancel := context.WithCancel(context.Background())
	return &KillSwitchPubSubAdapter{
		redisClient: redisClient,
		logger:      logger,
		cancelCtx:   cancel,
		ctx:         ctx,
	}
}

// safeCloseSub safely closes a PubSub subscription with proper synchronization
// Returns true if the subscription was closed, false if it was already nil
func (a *KillSwitchPubSubAdapter) safeCloseSub(logPattern string) bool {
	a.subMutex.Lock()
	defer a.subMutex.Unlock()

	if a.sub != nil {
		a.logger.Info(context.Background(), "Closing PubSub subscription", "pattern", logPattern)

		// Handle the case where Redis client might already be closed
		if err := a.sub.Close(); err != nil {
			// Only log non-client-closed errors as errors
			errMsg := err.Error()
			if errMsg == "redis: client is closed" {
				a.logger.Info(context.Background(), "PubSub close: Redis client already closed", "pattern", logPattern)
			} else {
				a.logger.Error(context.Background(), "Error closing PubSub subscription", "pattern", logPattern, "error", err)
			}
		} else {
			a.logger.Info(context.Background(), "PubSub subscription closed successfully", "pattern", logPattern)
		}

		a.sub = nil
		return true
	}
	return false
}

// safeSetSub safely sets the PubSub subscription with proper synchronization
func (a *KillSwitchPubSubAdapter) safeSetSub(newSub *redis.PubSub) {
	a.subMutex.Lock()
	defer a.subMutex.Unlock()
	a.sub = newSub
}

// safeGetChannel safely gets the message channel from the current subscription
func (a *KillSwitchPubSubAdapter) safeGetChannel() <-chan *redis.Message {
	a.subMutex.Lock()
	defer a.subMutex.Unlock()

	if a.sub != nil {
		return a.sub.Channel()
	}
	return nil
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

	// Add this goroutine to the WaitGroup before starting it
	a.wg.Add(1)
	go func() {
		defer func() {
			// Mark this goroutine as done when it exits
			a.wg.Done()

			if r := recover(); r != nil {
				a.logger.Error(context.Background(), "Panic recovered in persistent Redis PubSub routine",
					"pattern", pattern, "panic_info", fmt.Sprintf("%v", r), "stacktrace", string(debug.Stack()))
			}
			// Ensure subscription is closed if this goroutine exits using thread-safe method
			a.safeCloseSub(pattern)
			a.logger.Info(context.Background(), "Persistent subscription routine for Redis pattern has exited", "pattern", pattern)
		}()

		initialRetryDelay := 2 * time.Second // Start with a shorter delay
		maxRetryDelay := 30 * time.Second    // Max delay between retries
		currentRetryDelay := initialRetryDelay

		for {
			// Check for context cancellation at the beginning of each attempt cycle.
			select {
			case <-a.ctx.Done():
				a.logger.Info(context.Background(), "Adapter context cancelled, stopping persistent subscription attempts.", "pattern", pattern)
				return
			case <-ctx.Done():
				a.logger.Info(ctx, "Caller context cancelled, stopping persistent subscription attempts.", "pattern", pattern)
				return
			default:
				// Continue to attempt subscription
			}

			a.logger.Info(ctx, "Attempting to establish Redis PSubscribe", "pattern", pattern, "current_retry_delay_if_needed", currentRetryDelay.String())

			// Create a new PubSub object for this attempt.
			// Use a combined context that respects both the caller's context and the adapter's internal context
			combinedCtx, cancel := context.WithCancel(ctx)
			go func() {
				select {
				case <-a.ctx.Done():
					cancel()
				case <-combinedCtx.Done():
				}
			}()

			psCtx := a.redisClient.PSubscribe(combinedCtx, pattern)

			// Wait for subscription confirmation
			_, err := psCtx.Receive(combinedCtx)
			if err != nil {
				cancel()
				a.logger.Error(ctx, "Failed to establish or confirm Redis PSubscribe", "pattern", pattern, "error", err, "next_retry_in", currentRetryDelay.String())
				if psCtx != nil {
					_ = psCtx.Close() // Close the PubSub object from this failed attempt.
				}

				// Check if we should stop due to adapter shutdown
				select {
				case <-a.ctx.Done():
					a.logger.Info(context.Background(), "Adapter context cancelled during retry, stopping subscription attempts.", "pattern", pattern)
					return
				default:
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
				case <-a.ctx.Done():
					a.logger.Info(context.Background(), "Adapter context cancelled during retry wait, stopping subscription attempts.", "pattern", pattern)
					cancel()
					return
				case <-ctx.Done():
					a.logger.Info(ctx, "Caller context cancelled during PSubscribe retry wait", "pattern", pattern)
					cancel()
					return
				}
			}

			// Subscription successful
			a.logger.Info(ctx, "Successfully subscribed to Redis pattern, entering message processing loop", "pattern", pattern)
			a.safeSetSub(psCtx)                   // Use thread-safe method to store the confirmed, active subscription
			currentRetryDelay = initialRetryDelay // Reset retry delay on successful subscription.

			msgChan := a.safeGetChannel()
			if msgChan == nil {
				// This shouldn't happen since we just set the subscription, but let's be safe
				a.logger.Error(ctx, "Failed to get message channel after successful subscription", "pattern", pattern)
				cancel()
				continue // Retry subscription
			}

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

				case <-a.ctx.Done():
					a.logger.Info(context.Background(), "Adapter context cancelled (during message processing). Stopping Redis message processor and subscription routine.", "pattern", pattern)
					processingMessages = false // Exit inner loop.
					cancel()
					// The main defer in this goroutine will handle a.sub.Close() if a.sub is not nil.
					return // Exit the main goroutine.
				case <-ctx.Done():
					a.logger.Info(ctx, "Caller context cancelled (during message processing). Stopping Redis message processor and subscription routine.", "pattern", pattern)
					processingMessages = false // Exit inner loop.
					cancel()
					// The main defer in this goroutine will handle a.sub.Close() if a.sub is not nil.
					return // Exit the main goroutine.
				}
			} // End of message processing (inner) loop

			cancel() // Cancel the combined context for this iteration

			// If we exited the inner loop because msgChan closed, we need to clean up
			// the current subscription before the outer loop tries to PSubscribe again.
			// Use thread-safe method to close and clear the subscription.
			a.safeCloseSub(pattern)

			// Check if we should stop due to adapter shutdown before attempting to resubscribe
			select {
			case <-a.ctx.Done():
				a.logger.Info(context.Background(), "Adapter context cancelled, not attempting resubscription.", "pattern", pattern)
				return
			default:
				// Continue to resubscription attempt
			}

			// Small pause before the outer loop retries PSubscribe, to prevent rapid spinning if Redis is down.
			// This is in addition to currentRetryDelay used when PSubscribe itself fails.
			// This handles the case where the channel closes cleanly but we want to retry.
			select {
			case <-time.After(initialRetryDelay / 2): // A small, fixed delay.
			case <-a.ctx.Done():
				a.logger.Info(context.Background(), "Adapter context cancelled during brief pause before resubscription attempt", "pattern", pattern)
				return
			case <-ctx.Done():
				a.logger.Info(ctx, "Caller context cancelled during brief pause before resubscription attempt", "pattern", pattern)
				return
			}
		} // End of main (outer) retry loop
	}() // End of the main goroutine for persistent subscription

	return nil // Return immediately, indicating the goroutine has been started.
}

// Close closes the Redis PubSub subscription if one is active.
// It signals the subscription goroutine to terminate by cancelling the adapter context
// and waits for all goroutines to complete before returning.
func (a *KillSwitchPubSubAdapter) Close() error {
	a.logger.Info(context.Background(), "Close called on KillSwitchPubSubAdapter")

	// Cancel the adapter context first to signal all goroutines to stop
	if a.cancelCtx != nil {
		a.logger.Info(context.Background(), "Cancelling adapter context to stop all subscription goroutines...")
		a.cancelCtx()
	}

	// Close any active subscription using thread-safe method
	a.safeCloseSub("Close-method")

	// Wait for all subscription goroutines to complete
	a.logger.Info(context.Background(), "Waiting for Redis pub/sub goroutines to complete...")
	a.wg.Wait()
	a.logger.Info(context.Background(), "All Redis pub/sub goroutines have completed.")

	return nil
}
