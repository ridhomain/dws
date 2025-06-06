package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)

const (
	backpressurePolicyDropOldest = "drop_oldest"
	backpressurePolicyBlock      = "block"
)

// Connection wraps a websocket.Conn and adds buffering and lifecycle management.
type Connection struct {
	wsConn              *websocket.Conn
	logger              domain.Logger
	config              *config.AppConfig
	mu                  sync.Mutex // Protects wsConn for writes, and lastPongTime
	lastPongTime        time.Time
	connCtx             context.Context    // Overall context for the connection's lifetime
	cancelConnCtxFunc   context.CancelFunc // Cancels connCtx
	writeTimeoutSeconds int
	pingIntervalSeconds int
	pongWaitSeconds     int
	remoteAddrStr       string
	currentChatID       string
	currentChatIDMu     sync.Mutex

	// New fields for buffering and backpressure
	sessionKey      string // For metrics labeling
	messageBuffer   chan []byte
	bufferCapacity  int
	dropPolicy      string
	writerWg        sync.WaitGroup
	isWriterRunning bool
	writerMu        sync.Mutex // Protects isWriterRunning
}

// NewConnection creates a new managed WebSocket connection.
func NewConnection(
	connCtx context.Context,
	cancelFunc context.CancelFunc,
	wsConn *websocket.Conn,
	remoteAddr string,
	logger domain.Logger,
	cfgProvider config.Provider,
	sessionKey string, // Added sessionKey for metrics
) *Connection {
	appCfg := cfgProvider.Get().App
	bufferCap := appCfg.WebsocketMessageBufferSize
	if bufferCap <= 0 {
		bufferCap = 100 // Default buffer size
		logger.Warn(connCtx, "WebsocketMessageBufferSize not configured or invalid, using default", "default_size", bufferCap)
	}
	dropPol := strings.ToLower(appCfg.WebsocketBackpressureDropPolicy)
	if dropPol != backpressurePolicyDropOldest && dropPol != backpressurePolicyBlock {
		logger.Warn(connCtx, "Invalid WebsocketBackpressureDropPolicy, defaulting to drop_oldest", "configured_policy", appCfg.WebsocketBackpressureDropPolicy, "default_policy", backpressurePolicyDropOldest)
		dropPol = backpressurePolicyDropOldest
	}

	c := &Connection{
		wsConn:              wsConn,
		logger:              logger,
		config:              &appCfg,
		lastPongTime:        time.Now(),
		connCtx:             connCtx,
		cancelConnCtxFunc:   cancelFunc,
		writeTimeoutSeconds: appCfg.WriteTimeoutSeconds,
		pingIntervalSeconds: appCfg.PingIntervalSeconds,
		pongWaitSeconds:     appCfg.PongWaitSeconds,
		remoteAddrStr:       remoteAddr,
		currentChatID:       "",
		sessionKey:          sessionKey,
		messageBuffer:       make(chan []byte, bufferCap),
		bufferCapacity:      bufferCap,
		dropPolicy:          dropPol,
		isWriterRunning:     false,
	}

	metrics.SetWebsocketBufferCapacity(c.sessionKey, float64(c.bufferCapacity))
	c.startWriter()
	return c
}

func (c *Connection) startWriter() {
	c.writerMu.Lock()
	if c.isWriterRunning {
		c.writerMu.Unlock()
		return
	}
	c.isWriterRunning = true
	c.writerMu.Unlock()

	c.writerWg.Add(1)
	safego.Execute(c.connCtx, c.logger, fmt.Sprintf("WebSocketWriter-%s", c.sessionKey), func() {
		defer c.writerWg.Done()
		c.logger.Info(c.connCtx, "WebSocket writer goroutine started", "sessionKey", c.sessionKey)

		// Track consecutive write failures for circuit breaking
		consecutiveFailures := 0
		maxConsecutiveFailures := 5

		for {
			select {
			case <-c.connCtx.Done():
				c.logger.Info(c.connCtx, "Connection context done, stopping WebSocket writer.", "sessionKey", c.sessionKey)
				return
			case msgBytes, ok := <-c.messageBuffer:
				if !ok {
					c.logger.Info(c.connCtx, "Message buffer closed, stopping WebSocket writer.", "sessionKey", c.sessionKey)
					return
				}

				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))

				// Parse message for logging (existing code)
				var messageType string = "unknown"
				var messageID string = ""
				var parsedMsg map[string]interface{}
				if jsonErr := json.Unmarshal(msgBytes, &parsedMsg); jsonErr == nil {
					if msgType, ok := parsedMsg["type"].(string); ok {
						messageType = msgType
					}
					if messageType == domain.MessageTypeEvent {
						if payload, ok := parsedMsg["payload"].(map[string]interface{}); ok {
							if evID, ok := payload["event_id"].(string); ok {
								messageID = evID
							}
						}
					}
				}

				// Set write timeout
				writeTimeout := time.Duration(c.writeTimeoutSeconds) * time.Second
				if writeTimeout <= 0 {
					writeTimeout = 10 * time.Second
				}

				// CRITICAL FIX: Use background context for write operations
				// This prevents the write from being cancelled when connection is closing
				writeCtx, writeCancel := context.WithTimeout(context.Background(), writeTimeout)

				c.mu.Lock()

				// Check if connection is valid
				if c.wsConn == nil {
					c.mu.Unlock()
					writeCancel()
					c.logger.Warn(c.connCtx, "WebSocket connection is nil, stopping writer",
						"session_key", c.sessionKey)
					return
				}

				// Attempt write
				writeStartTime := time.Now()
				err := c.wsConn.Write(writeCtx, websocket.MessageText, msgBytes)
				writeDuration := time.Since(writeStartTime)

				c.mu.Unlock()
				writeCancel()

				if err != nil {
					consecutiveFailures++

					// Determine error severity
					isFatal := false
					errorType := "unknown"

					if errors.Is(err, context.DeadlineExceeded) {
						errorType = "timeout"
						c.logger.Warn(c.connCtx, "WebSocket write timeout",
							"error", err.Error(),
							"session_key", c.sessionKey,
							"message_type", messageType,
							"message_id", messageID,
							"write_duration_ms", writeDuration.Milliseconds(),
							"consecutive_failures", consecutiveFailures)
					} else if errors.Is(err, context.Canceled) {
						errorType = "canceled"
						// Write context was cancelled, but check if connection is closing
						select {
						case <-c.connCtx.Done():
							// Connection is closing, this is expected
							c.logger.Info(c.connCtx, "Write cancelled due to connection closing",
								"session_key", c.sessionKey)
							return
						default:
							// Just the write was cancelled, continue
							c.logger.Debug(c.connCtx, "Write context cancelled but connection still active",
								"session_key", c.sessionKey)
						}
					} else if websocket.CloseStatus(err) != -1 {
						// This is a WebSocket close error
						errorType = "websocket_closed"
						isFatal = true
						c.logger.Error(c.connCtx, "WebSocket closed with status",
							"error", err.Error(),
							"close_status", websocket.CloseStatus(err),
							"session_key", c.sessionKey,
							"message_type", messageType,
							"message_id", messageID)
					} else if strings.Contains(err.Error(), "use of closed network connection") ||
						strings.Contains(err.Error(), "broken pipe") ||
						strings.Contains(err.Error(), "connection reset by peer") {
						errorType = "network_closed"
						isFatal = true
						c.logger.Error(c.connCtx, "Network connection closed",
							"error", err.Error(),
							"session_key", c.sessionKey,
							"message_type", messageType,
							"message_id", messageID)
					} else {
						// Other errors - might be temporary
						errorType = "other"
						c.logger.Error(c.connCtx, "WebSocket write error",
							"error", err.Error(),
							"error_type", fmt.Sprintf("%T", err),
							"session_key", c.sessionKey,
							"message_type", messageType,
							"message_id", messageID,
							"consecutive_failures", consecutiveFailures)
					}

					// Only close connection for fatal errors or too many consecutive failures
					if isFatal || consecutiveFailures >= maxConsecutiveFailures {
						c.logger.Error(c.connCtx, "Stopping writer due to fatal error or too many failures",
							"fatal", isFatal,
							"consecutive_failures", consecutiveFailures,
							"error_type", errorType,
							"session_key", c.sessionKey)

						// DON'T immediately cancel connection context
						// Instead, let the read loop detect the closed connection
						// This prevents race conditions and abnormal closures

						// Just exit the writer goroutine
						return
					}

					// For non-fatal errors, continue after a small backoff
					backoffMs := min(100*consecutiveFailures, 1000) // Max 1 second
					time.Sleep(time.Duration(backoffMs) * time.Millisecond)

				} else {
					// Success - reset failure counter
					if consecutiveFailures > 0 {
						c.logger.Info(c.connCtx, "WebSocket write recovered after failures",
							"previous_failures", consecutiveFailures,
							"session_key", c.sessionKey)
						consecutiveFailures = 0
					}

					c.logger.Debug(c.connCtx, "Successfully wrote message to WebSocket",
						"message_type", messageType,
						"message_id", messageID,
						"message_bytes", len(msgBytes),
						"write_duration_ms", writeDuration.Milliseconds(),
						"session_key", c.sessionKey)
				}
			}
		}
	})
}

// Context returns the context associated with this connection.
func (c *Connection) Context() context.Context {
	return c.connCtx
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Close attempts to close the WebSocket connection with a specified status code and reason.
// It also ensures the writer goroutine is stopped.
// Also fix the Close method to be more graceful
func (c *Connection) Close(statusCode websocket.StatusCode, reason string) error {
	c.logger.Info(c.connCtx, "Connection.Close called",
		"statusCode", statusCode,
		"reason", reason,
		"sessionKey", c.sessionKey)

	// First, close the message buffer to stop accepting new messages
	c.writerMu.Lock()
	if c.isWriterRunning && c.messageBuffer != nil {
		close(c.messageBuffer)
		c.isWriterRunning = false
	}
	c.writerMu.Unlock()

	// Give writer goroutine a moment to process remaining messages
	done := make(chan struct{})
	go func() {
		c.writerWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Writer finished gracefully
	case <-time.After(2 * time.Second):
		// Timeout waiting for writer
		c.logger.Warn(c.connCtx, "Timeout waiting for writer to finish", "sessionKey", c.sessionKey)
	}

	// Now close the WebSocket connection
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.wsConn == nil {
		return errors.New("WebSocket connection is already nil")
	}

	// Send close frame to client
	err := c.wsConn.Close(statusCode, reason)
	c.wsConn = nil

	// Finally cancel the context
	if c.cancelConnCtxFunc != nil {
		c.cancelConnCtxFunc()
		c.cancelConnCtxFunc = nil
	}

	return err
}

// CloseWithError sends an error message to the client and then closes the WebSocket connection
// with the appropriate close code derived from the error response.
func (c *Connection) CloseWithError(errResp domain.ErrorResponse, reason string) error {
	c.logger.Warn(c.connCtx, "Closing connection with error", "code", errResp.Code, "message", errResp.Message, "details", errResp.Details, "reason", reason, "sessionKey", c.sessionKey)
	// First try to send the error message to the client via the buffer
	errorMsgPayload := domain.NewErrorMessage(errResp)
	if err := c.WriteJSON(errorMsgPayload); err != nil { // This will use the buffer
		c.logger.Error(c.connCtx, "Failed to queue error message before closing connection",
			"error", err.Error(),
			"error_code", string(errResp.Code),
			"message", errResp.Message,
			"sessionKey", c.sessionKey)
	} else {
		// Metric for sent error message is handled in WriteJSON logic if successful
	}
	closeCode := errResp.ToWebSocketCloseCode()
	return c.Close(closeCode, reason) // This will handle stopping writer and closing wsConn
}

// WriteJSON marshals the value to JSON and attempts to send it to the message buffer.
// Returns an error if marshalling fails or if the buffer send operation fails according to policy.
func (c *Connection) WriteJSON(v interface{}) error {
	// Extract message type and uniqueness info for metrics and logging
	var messageTypeForMetric string = "unknown"
	var messageID string = ""
	var eventID string = ""

	// Try to extract message type
	if bm, ok := v.(domain.BaseMessage); ok {
		messageTypeForMetric = bm.Type

		// Try to extract event payload for uniqueness tracking
		if messageTypeForMetric == domain.MessageTypeEvent {
			if payload, ok := bm.Payload.(map[string]interface{}); ok {
				if evID, ok := payload["event_id"].(string); ok && evID != "" {
					eventID = evID
					messageID = evID
				}
			}
		}
	}

	// Debug log for message delivery attempt
	c.logger.Debug(c.connCtx, "Attempting to write message to WebSocket buffer",
		"message_type", messageTypeForMetric,
		"event_id", eventID,
		"message_id", messageID,
		"session_key", c.sessionKey,
		"operation", "WriteJSON")

	msgBytes, err := json.Marshal(v)
	if err != nil {
		c.logger.Error(c.connCtx, "Failed to marshal JSON for WriteJSON",
			"error", err.Error(),
			"session_key", c.sessionKey,
			"message_type", messageTypeForMetric,
			"message_id", messageID)
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Validate JSON before sending
	if !json.Valid(msgBytes) {
		c.logger.Error(c.connCtx, "Invalid JSON being sent!",
			"type", fmt.Sprintf("%T", v),
			"session_key", c.sessionKey)
	}

	// Log message size if it's large
	if len(msgBytes) > 10000 { // 10KB
		c.logger.Warn(c.connCtx, "Large message being sent",
			"size_bytes", len(msgBytes),
			"size_kb", len(msgBytes)/1024,
			"message_type", messageTypeForMetric,
			"session_key", c.sessionKey)
	}

	select {
	case <-c.connCtx.Done():
		c.logger.Warn(c.connCtx, "Connection context done, cannot write message to buffer",
			"session_key", c.sessionKey,
			"message_type", messageTypeForMetric,
			"message_id", messageID)
		return c.connCtx.Err()
	default:
		// Proceed to try sending to buffer
	}

	// Check if writer is running before attempting to send to buffer
	c.writerMu.Lock()
	if !c.isWriterRunning {
		c.writerMu.Unlock()
		c.logger.Warn(c.connCtx, "Writer not running, cannot write message to buffer",
			"session_key", c.sessionKey,
			"message_type", messageTypeForMetric,
			"message_id", messageID)
		return fmt.Errorf("writer goroutine not running for session %s", c.sessionKey)
	}
	c.writerMu.Unlock()

	if len(c.messageBuffer) >= c.bufferCapacity { // Buffer is full
		metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
		c.logger.Warn(c.connCtx, "WebSocket send buffer is full",
			"session_key", c.sessionKey,
			"capacity", c.bufferCapacity,
			"policy", c.dropPolicy,
			"message_type", messageTypeForMetric,
			"message_id", messageID)
		if c.dropPolicy == backpressurePolicyDropOldest {
			select {
			case oldestMsg := <-c.messageBuffer: // Remove oldest
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_dropped_oldest")
				c.logger.Debug(c.connCtx, "Dropped oldest message from buffer due to backpressure",
					"session_key", c.sessionKey,
					"dropped_msg_len", len(oldestMsg),
					"message_type", messageTypeForMetric,
					"message_id", messageID,
					"operation", "WriteJSON")
			default:
				// Should not happen if len(c.messageBuffer) >= c.bufferCapacity
				c.logger.Error(c.connCtx, "Buffer full but could not dequeue oldest message (unexpected state)",
					"session_key", c.sessionKey,
					"message_type", messageTypeForMetric,
					"message_id", messageID)
				// Still attempt to send, might block if chan is unbuffered and full due to race
			}
			// Try to send the new message after attempting to drop one
			select {
			case c.messageBuffer <- msgBytes:
				metrics.IncrementMessagesSent(messageTypeForMetric) // Count as sent if successfully buffered
				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
				c.logger.Debug(c.connCtx, "Successfully queued message to buffer after dropping oldest",
					"session_key", c.sessionKey,
					"message_type", messageTypeForMetric,
					"message_id", messageID,
					"buffer_used", len(c.messageBuffer),
					"operation", "WriteJSON")
				return nil
			default: // Should ideally not happen if buffer has capacity now
				c.logger.Error(c.connCtx, "Failed to send message to buffer even after dropping oldest (buffer likely still full)",
					"session_key", c.sessionKey,
					"message_type", messageTypeForMetric,
					"message_id", messageID)
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_post_drop_fail")
				return fmt.Errorf("failed to send to buffer for session %s after dropping oldest", c.sessionKey)
			}
		} else if c.dropPolicy == backpressurePolicyBlock {
			// Block until there's space or context is done.
			c.logger.Debug(c.connCtx, "Blocking on WebSocket send buffer (policy: block)",
				"session_key", c.sessionKey,
				"message_type", messageTypeForMetric,
				"message_id", messageID,
				"operation", "WriteJSON")
			select {
			case c.messageBuffer <- msgBytes:
				metrics.IncrementMessagesSent(messageTypeForMetric) // Count as sent if successfully buffered
				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
				c.logger.Debug(c.connCtx, "Successfully queued message to buffer after blocking",
					"session_key", c.sessionKey,
					"message_type", messageTypeForMetric,
					"message_id", messageID,
					"buffer_used", len(c.messageBuffer),
					"operation", "WriteJSON")
				return nil
				// Slow client detection could be added here by timing how long this blocks.
				// If it blocks for too long, c.cancelConnCtxFunc() could be called.
			case <-c.connCtx.Done():
				c.logger.Warn(c.connCtx, "Connection context done while blocked on send buffer",
					"session_key", c.sessionKey,
					"message_type", messageTypeForMetric,
					"message_id", messageID)
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_block_ctx_done")
				return c.connCtx.Err()
			}
		} else { // Should not happen if policy is validated at init
			c.logger.Error(c.connCtx, "Unknown backpressure drop policy",
				"policy", c.dropPolicy,
				"session_key", c.sessionKey,
				"message_type", messageTypeForMetric,
				"message_id", messageID)
			metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "unknown_policy")
			return fmt.Errorf("unknown backpressure policy: %s for session %s", c.dropPolicy, c.sessionKey)
		}
	}

	// Buffer is not full, try to send non-blockingly first
	select {
	case c.messageBuffer <- msgBytes:
		metrics.IncrementMessagesSent(messageTypeForMetric) // Count as sent if successfully buffered
		metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
		c.logger.Debug(c.connCtx, "Successfully queued message to buffer (non-blocking)",
			"session_key", c.sessionKey,
			"message_type", messageTypeForMetric,
			"message_id", messageID,
			"buffer_used", len(c.messageBuffer),
			"operation", "WriteJSON")
		return nil
	default:
		// This case might happen due to a race condition if the buffer filled up
		// between the len check and this select. Retry with blocking semantics
		// based on the policy (which is effectively what the "buffer is full" logic above does).
		c.logger.Warn(c.connCtx, "Buffer filled during non-blocking send attempt, retrying with policy",
			"session_key", c.sessionKey,
			"message_type", messageTypeForMetric,
			"message_id", messageID)
		// Re-evaluate policy (this is a bit duplicative of the logic above, could be refactored)
		if len(c.messageBuffer) >= c.bufferCapacity { // Confirm buffer is still full
			if c.dropPolicy == backpressurePolicyDropOldest {
				select {
				case <-c.messageBuffer:
					metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_race_dropped_oldest")
					c.logger.Debug(c.connCtx, "Dropped oldest message due to race condition",
						"session_key", c.sessionKey,
						"message_type", messageTypeForMetric,
						"message_id", messageID,
						"operation", "WriteJSON")
				default:
				}
				select {
				case c.messageBuffer <- msgBytes:
					metrics.IncrementMessagesSent(messageTypeForMetric)
					metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
					c.logger.Debug(c.connCtx, "Successfully queued message after race condition handling",
						"session_key", c.sessionKey,
						"message_type", messageTypeForMetric,
						"message_id", messageID,
						"buffer_used", len(c.messageBuffer),
						"operation", "WriteJSON")
					return nil
				default:
					metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_race_drop_fail")
					return fmt.Errorf("failed to send to buffer (race) for session %s after dropping", c.sessionKey)
				}
			} else if c.dropPolicy == backpressurePolicyBlock {
				select {
				case c.messageBuffer <- msgBytes:
					metrics.IncrementMessagesSent(messageTypeForMetric)
					metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
					c.logger.Debug(c.connCtx, "Successfully queued message after race condition with blocking policy",
						"session_key", c.sessionKey,
						"message_type", messageTypeForMetric,
						"message_id", messageID,
						"buffer_used", len(c.messageBuffer),
						"operation", "WriteJSON")
					return nil
				case <-c.connCtx.Done():
					metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_race_block_ctx_done")
					return c.connCtx.Err()
				}
			}
		}
		// If it wasn't full, but the non-blocking send failed, this is an odd state.
		// Try one more blocking send.
		select {
		case c.messageBuffer <- msgBytes:
			metrics.IncrementMessagesSent(messageTypeForMetric)
			metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
			c.logger.Debug(c.connCtx, "Successfully queued message after unexpected state",
				"session_key", c.sessionKey,
				"message_type", messageTypeForMetric,
				"message_id", messageID,
				"buffer_used", len(c.messageBuffer),
				"operation", "WriteJSON")
			return nil
		case <-time.After(100 * time.Millisecond): // Short timeout to prevent indefinite block on unexpected state
			c.logger.Error(c.connCtx, "Failed to send message to buffer after non-blocking attempt and re-check (unexpected)",
				"session_key", c.sessionKey,
				"message_type", messageTypeForMetric,
				"message_id", messageID)
			metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_send_timeout_unexpected")
			return fmt.Errorf("timed out sending to buffer for session %s (unexpected state)", c.sessionKey)
		case <-c.connCtx.Done():
			c.logger.Warn(c.connCtx, "Connection context done while trying to send to buffer (unexpected state)",
				"session_key", c.sessionKey,
				"message_type", messageTypeForMetric,
				"message_id", messageID)
			metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_send_ctx_done_unexpected")
			return c.connCtx.Err()
		}
	}
}

// ReadMessage reads a data message from the WebSocket connection.
// Control frames (like pongs) are handled by the library and not returned here.
func (c *Connection) ReadMessage(ctx context.Context) (websocket.MessageType, []byte, error) {
	// The underlying c.wsConn.Read(ctx) handles control frames (ping/pong) internally.
	// It only returns data messages (Text or Binary) or an error.
	return c.wsConn.Read(ctx)
}

// RemoteAddr returns the remote network address string of the client.
func (c *Connection) RemoteAddr() string {
	return c.remoteAddrStr
}

// UnderlyingConn returns the underlying *websocket.Conn.
func (c *Connection) UnderlyingConn() *websocket.Conn {
	return c.wsConn
}

// LastPongTime returns the time the last pong was received (or when connection was established).
// This will be accurately updated by the OnPongReceived callback configured in the handler.
func (c *Connection) LastPongTime() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPongTime
}

// UpdateLastPongTime is called by the OnPongReceived callback in the handler.
func (c *Connection) UpdateLastPongTime() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastPongTime = time.Now()
}

// Ping sends a ping message to the client.
func (c *Connection) Ping(ctx context.Context) error {
	c.mu.Lock() // Protects wsConn
	defer c.mu.Unlock()

	if c.wsConn == nil { // Check if connection is already closed
		return errors.New("cannot ping: WebSocket connection is nil (likely closed)")
	}

	ctxToWrite := c.connCtx // Use connection's overall context for ping lifetime
	var cancel context.CancelFunc
	writeTimeout := time.Duration(c.writeTimeoutSeconds) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second // Default if not configured
	}
	// If the passed-in ctx has a shorter deadline, WithTimeout respects that.
	// If connCtx has a deadline (e.g. from overall request), that's also respected.
	ctxToWrite, cancel = context.WithTimeout(ctxToWrite, writeTimeout)
	defer cancel()

	return c.wsConn.Ping(ctxToWrite)
}

// GetCurrentChatID safely retrieves the current chat ID for the connection.
func (c *Connection) GetCurrentChatID() string {
	c.currentChatIDMu.Lock()
	defer c.currentChatIDMu.Unlock()
	return c.currentChatID
}

// SetCurrentChatID safely sets the current chat ID for the connection.
func (c *Connection) SetCurrentChatID(chatID string) {
	c.currentChatIDMu.Lock()
	defer c.currentChatIDMu.Unlock()
	c.currentChatID = chatID
}

// GetSessionKey returns the session key associated with this connection.
func (c *Connection) GetSessionKey() string {
	return c.sessionKey
}
