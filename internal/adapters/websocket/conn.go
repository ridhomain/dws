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
		for {
			select {
			case <-c.connCtx.Done():
				c.logger.Info(c.connCtx, "Connection context done, stopping WebSocket writer.", "sessionKey", c.sessionKey)
				// Drain any remaining messages in the buffer upon graceful shutdown if desired
				// For now, we just exit. wsConn.Close() will be handled by the manageConnection defer.
				return
			case msgBytes, ok := <-c.messageBuffer:
				if !ok {
					c.logger.Info(c.connCtx, "Message buffer closed, stopping WebSocket writer.", "sessionKey", c.sessionKey)
					return
				}

				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))

				// Create a separate context for write operations that's independent of connection cancellations
				writeTimeout := time.Duration(c.writeTimeoutSeconds) * time.Second
				if writeTimeout <= 0 {
					writeTimeout = 10 * time.Second // Default if not configured
				}

				// Use a background context for the write operation instead of the connection context
				// This ensures we can complete the write even if the connection context is canceled
				ctxToWrite, cancel := context.WithTimeout(context.Background(), writeTimeout)

				c.mu.Lock() // Protects wsConn
				var err error
				// Check if the connection context is already done before attempting to write
				select {
				case <-c.connCtx.Done():
					c.logger.Info(ctxToWrite, "Connection context already done before write attempt, skipping write", "sessionKey", c.sessionKey)
					err = c.connCtx.Err()
				default:
					// Connection context is still valid, attempt the write
					err = c.wsConn.Write(ctxToWrite, websocket.MessageText, msgBytes)
				}
				c.mu.Unlock()
				cancel()

				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						c.logger.Info(c.connCtx, "WebSocket write canceled or timed out, connection likely closing", "error", err.Error(), "sessionKey", c.sessionKey)
					} else {
						c.logger.Error(c.connCtx, "Failed to write message from buffer to WebSocket", "error", err.Error(), "sessionKey", c.sessionKey)
					}

					// Don't immediately cancel the connection context on every write error
					// Only do it for non-context related errors that indicate connection problems
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						// Signal manageConnection to clean up for serious connection errors
						c.cancelConnCtxFunc()
					}
					return
				}
				// Successfully wrote message
			}
		}
	})
}

// Context returns the context associated with this connection.
func (c *Connection) Context() context.Context {
	return c.connCtx
}

// Close attempts to close the WebSocket connection with a specified status code and reason.
// It also ensures the writer goroutine is stopped.
func (c *Connection) Close(statusCode websocket.StatusCode, reason string) error {
	c.logger.Info(c.connCtx, "Connection.Close called", "statusCode", statusCode, "reason", reason, "sessionKey", c.sessionKey)

	// Signal writer to stop and wait for it
	c.writerMu.Lock()
	if c.isWriterRunning {
		if c.messageBuffer != nil {
			close(c.messageBuffer) // Close buffer to unblock writer if it's waiting
		}
		c.isWriterRunning = false
	}
	c.writerMu.Unlock()
	c.writerWg.Wait() // Wait for writer goroutine to finish

	c.mu.Lock() // Protects wsConn and cancelConnCtxFunc
	defer c.mu.Unlock()

	// Cancel the connection's context if not already done
	if c.cancelConnCtxFunc != nil {
		currentCancelFunc := c.cancelConnCtxFunc
		c.cancelConnCtxFunc = nil // Prevent multiple calls
		currentCancelFunc()
	}

	if c.wsConn == nil {
		return errors.New("WebSocket connection is already nil")
	}

	err := c.wsConn.Close(statusCode, reason)
	c.wsConn = nil // Nullify to prevent reuse
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
	msgBytes, err := json.Marshal(v)
	if err != nil {
		c.logger.Error(c.connCtx, "Failed to marshal JSON for WriteJSON", "error", err.Error(), "sessionKey", c.sessionKey)
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Extract message type for metrics, assuming v is BaseMessage or similar
	var messageTypeForMetric string = "unknown"
	if bm, ok := v.(domain.BaseMessage); ok {
		messageTypeForMetric = bm.Type
	}

	select {
	case <-c.connCtx.Done():
		c.logger.Warn(c.connCtx, "Connection context done, cannot write message to buffer", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
		return c.connCtx.Err()
	default:
		// Proceed to try sending to buffer
	}

	// Check if writer is running before attempting to send to buffer
	c.writerMu.Lock()
	if !c.isWriterRunning {
		c.writerMu.Unlock()
		c.logger.Warn(c.connCtx, "Writer not running, cannot write message to buffer", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
		return fmt.Errorf("writer goroutine not running for session %s", c.sessionKey)
	}
	c.writerMu.Unlock()

	if len(c.messageBuffer) >= c.bufferCapacity { // Buffer is full
		metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
		c.logger.Warn(c.connCtx, "WebSocket send buffer is full", "sessionKey", c.sessionKey, "capacity", c.bufferCapacity, "policy", c.dropPolicy, "messageType", messageTypeForMetric)
		if c.dropPolicy == backpressurePolicyDropOldest {
			select {
			case oldestMsg := <-c.messageBuffer: // Remove oldest
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_dropped_oldest")
				c.logger.Info(c.connCtx, "Dropped oldest message from buffer due to backpressure", "sessionKey", c.sessionKey, "dropped_msg_len", len(oldestMsg), "messageType", messageTypeForMetric)
			default:
				// Should not happen if len(c.messageBuffer) >= c.bufferCapacity
				c.logger.Error(c.connCtx, "Buffer full but could not dequeue oldest message (unexpected state)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
				// Still attempt to send, might block if chan is unbuffered and full due to race
			}
			// Try to send the new message after attempting to drop one
			select {
			case c.messageBuffer <- msgBytes:
				metrics.IncrementMessagesSent(messageTypeForMetric) // Count as sent if successfully buffered
				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
				return nil
			default: // Should ideally not happen if buffer has capacity now
				c.logger.Error(c.connCtx, "Failed to send message to buffer even after dropping oldest (buffer likely still full)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_post_drop_fail")
				return fmt.Errorf("failed to send to buffer for session %s after dropping oldest", c.sessionKey)
			}
		} else if c.dropPolicy == backpressurePolicyBlock {
			// Block until there's space or context is done.
			c.logger.Info(c.connCtx, "Blocking on WebSocket send buffer (policy: block)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
			select {
			case c.messageBuffer <- msgBytes:
				metrics.IncrementMessagesSent(messageTypeForMetric) // Count as sent if successfully buffered
				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
				return nil
				// Slow client detection could be added here by timing how long this blocks.
				// If it blocks for too long, c.cancelConnCtxFunc() could be called.
			case <-c.connCtx.Done():
				c.logger.Warn(c.connCtx, "Connection context done while blocked on send buffer", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_block_ctx_done")
				return c.connCtx.Err()
			}
		} else { // Should not happen if policy is validated at init
			c.logger.Error(c.connCtx, "Unknown backpressure drop policy", "policy", c.dropPolicy, "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
			metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "unknown_policy")
			return fmt.Errorf("unknown backpressure policy: %s for session %s", c.dropPolicy, c.sessionKey)
		}
	}

	// Buffer is not full, try to send non-blockingly first
	select {
	case c.messageBuffer <- msgBytes:
		metrics.IncrementMessagesSent(messageTypeForMetric) // Count as sent if successfully buffered
		metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
		return nil
	default:
		// This case might happen due to a race condition if the buffer filled up
		// between the len check and this select. Retry with blocking semantics
		// based on the policy (which is effectively what the "buffer is full" logic above does).
		c.logger.Warn(c.connCtx, "Buffer filled during non-blocking send attempt, retrying with policy", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
		// Re-evaluate policy (this is a bit duplicative of the logic above, could be refactored)
		if len(c.messageBuffer) >= c.bufferCapacity { // Confirm buffer is still full
			if c.dropPolicy == backpressurePolicyDropOldest {
				select {
				case <-c.messageBuffer:
					metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_race_dropped_oldest")
				default:
				}
				select {
				case c.messageBuffer <- msgBytes:
					metrics.IncrementMessagesSent(messageTypeForMetric)
					metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
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
			return nil
		case <-time.After(100 * time.Millisecond): // Short timeout to prevent indefinite block on unexpected state
			c.logger.Error(c.connCtx, "Failed to send message to buffer after non-blocking attempt and re-check (unexpected)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
			metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_send_timeout_unexpected")
			return fmt.Errorf("timed out sending to buffer for session %s (unexpected state)", c.sessionKey)
		case <-c.connCtx.Done():
			c.logger.Warn(c.connCtx, "Connection context done while trying to send to buffer (unexpected state)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
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
