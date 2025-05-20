package websocket

import (
	"context"
	"encoding/json"
	"fmt" // For temporary marshalling error logging

	// For temporary marshalling error logging
	"sync"
	"time"

	"github.com/coder/websocket" // Direct import, no alias
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// Connection is a wrapper around the underlying websocket.Conn
type Connection struct {
	wsConn              *websocket.Conn
	logger              domain.Logger
	config              *config.AppConfig
	mu                  sync.Mutex
	lastPongTime        time.Time // This will be updated via OnPongReceived callback in handler
	connCtx             context.Context
	cancelConnCtxFunc   context.CancelFunc
	writeTimeoutSeconds int
	pingIntervalSeconds int
	pongWaitSeconds     int
	remoteAddrStr       string     // Storing remote address as a string
	currentChatID       string     // Added to store the current chat ID for this connection
	currentChatIDMu     sync.Mutex // Mutex to protect access to currentChatID
}

// NewConnection creates a new Connection wrapper.
func NewConnection(
	connCtx context.Context,
	cancelFunc context.CancelFunc,
	wsConn *websocket.Conn,
	remoteAddr string, // remoteAddr is passed in
	logger domain.Logger,
	cfgProvider config.Provider,
) *Connection {
	appCfg := cfgProvider.Get().App
	return &Connection{
		wsConn:              wsConn,
		logger:              logger,
		config:              &appCfg,
		lastPongTime:        time.Now(), // Initialized, will be updated by OnPongReceived
		connCtx:             connCtx,
		cancelConnCtxFunc:   cancelFunc,
		writeTimeoutSeconds: appCfg.WriteTimeoutSeconds,
		pingIntervalSeconds: appCfg.PingIntervalSeconds,
		pongWaitSeconds:     appCfg.PongWaitSeconds,
		remoteAddrStr:       remoteAddr, // Store the provided remote address string
		currentChatID:       "",         // currentChatID is initialized as empty string
	}
}

// Context returns the context associated with this connection.
func (c *Connection) Context() context.Context {
	return c.connCtx
}

// Close attempts to close the WebSocket connection with a specified status code and reason.
func (c *Connection) Close(statusCode websocket.StatusCode, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelConnCtxFunc != nil {
		c.cancelConnCtxFunc()
	}
	return c.wsConn.Close(statusCode, reason)
}

// CloseWithError sends an error message to the client and then closes the WebSocket connection
// with the appropriate close code derived from the error response.
func (c *Connection) CloseWithError(errResp domain.ErrorResponse, reason string) error {
	// First send the error message to the client
	errorMsg := domain.NewErrorMessage(errResp)
	if err := c.WriteJSON(errorMsg); err != nil {
		c.logger.Error(c.connCtx, "Failed to send error message before closing connection",
			"error", err.Error(),
			"error_code", string(errResp.Code),
			"message", errResp.Message)
		// Continue with close even if we couldn't send the error message
	} else {
		metrics.IncrementMessagesSent(domain.MessageTypeError)
	}

	// Then close the WebSocket with the appropriate status code
	closeCode := errResp.ToWebSocketCloseCode()
	return c.Close(closeCode, reason)
}

// WriteJSON sends a JSON-encoded message to the client with a timeout.
func (c *Connection) WriteJSON(v interface{}) error {
	payload, err := json.Marshal(v)
	if err != nil {
		c.logger.Error(c.connCtx, "Failed to marshal JSON for WriteJSON", "error", err.Error())
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ctxToWrite := c.connCtx
	var cancel context.CancelFunc
	if c.writeTimeoutSeconds > 0 {
		ctxToWrite, cancel = context.WithTimeout(c.connCtx, time.Duration(c.writeTimeoutSeconds)*time.Second)
		defer cancel()
	}
	return c.wsConn.Write(ctxToWrite, websocket.MessageText, payload) // Used websocketlib
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
	c.mu.Lock()
	defer c.mu.Unlock()

	ctxToWrite := c.connCtx
	var cancel context.CancelFunc
	if c.writeTimeoutSeconds > 0 { // Use write timeout for ping as well
		ctxToWrite, cancel = context.WithTimeout(c.connCtx, time.Duration(c.writeTimeoutSeconds)*time.Second)
		defer cancel()
	}
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

// marshalToJSON helper is removed as per previous decision.
// If needed, it should be: func marshalToJSON(v interface{}) ([]byte, error)
