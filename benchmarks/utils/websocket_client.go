package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// BackpressurePolicy defines how to handle buffer overflow
type BackpressurePolicy string

const (
	BackpressureDrop   BackpressurePolicy = "drop_oldest"
	BackpressureBlock  BackpressurePolicy = "block"
	BackpressureReject BackpressurePolicy = "reject"
)

// ConnectionState represents the state of a WebSocket connection
type ConnectionState int

const (
	StateConnecting ConnectionState = iota
	StateConnected
	StateDisconnecting
	StateDisconnected
	StateError
)

// MockWebSocketConnection simulates a WebSocket connection for benchmarking
type MockWebSocketConnection struct {
	id                 string
	state              ConnectionState
	sendBuffer         chan []byte
	receiveBuffer      chan []byte
	backpressurePolicy BackpressurePolicy
	bufferSize         int
	mu                 sync.RWMutex

	// Connection metadata
	companyID string
	agentID   string
	userID    string
	token     string

	// Metrics
	MessagesSent     int64
	MessagesReceived int64
	MessagesDropped  int64
	BytesSent        int64
	BytesReceived    int64
	ConnectedAt      time.Time
	LastActivity     time.Time

	// Callbacks for testing
	OnMessage func(data []byte)
	OnClose   func(code int, reason string)
	OnError   func(err error)

	// Control channels
	closeSignal chan struct{}
	errorSignal chan error
	closed      bool
}

// NewMockWebSocketConnection creates a new mock WebSocket connection
func NewMockWebSocketConnection(id, companyID, agentID, userID, token string, bufferSize int, policy BackpressurePolicy) *MockWebSocketConnection {
	return &MockWebSocketConnection{
		id:                 id,
		companyID:          companyID,
		agentID:            agentID,
		userID:             userID,
		token:              token,
		state:              StateConnecting,
		sendBuffer:         make(chan []byte, bufferSize),
		receiveBuffer:      make(chan []byte, bufferSize),
		backpressurePolicy: policy,
		bufferSize:         bufferSize,
		ConnectedAt:        time.Now(),
		LastActivity:       time.Now(),
		closeSignal:        make(chan struct{}),
		errorSignal:        make(chan error, 1),
	}
}

// Connect simulates establishing a WebSocket connection
func (c *MockWebSocketConnection) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateConnecting {
		return fmt.Errorf("connection is not in connecting state")
	}

	c.state = StateConnected
	c.ConnectedAt = time.Now()
	c.LastActivity = time.Now()

	// Start message processing goroutines
	go c.processSendBuffer()
	go c.processReceiveBuffer()

	return nil
}

// SendMessage sends a message through the WebSocket connection
func (c *MockWebSocketConnection) SendMessage(data []byte) error {
	c.mu.RLock()
	if c.state != StateConnected {
		c.mu.RUnlock()
		return fmt.Errorf("connection is not connected")
	}
	c.mu.RUnlock()

	select {
	case c.sendBuffer <- data:
		atomic.AddInt64(&c.MessagesSent, 1)
		atomic.AddInt64(&c.BytesSent, int64(len(data)))
		c.updateLastActivity()
		return nil

	default:
		// Buffer is full, apply backpressure policy
		return c.handleBackpressure(data, c.sendBuffer)
	}
}

// ReceiveMessage simulates receiving a message from the WebSocket
func (c *MockWebSocketConnection) ReceiveMessage(data []byte) error {
	c.mu.RLock()
	if c.state != StateConnected {
		c.mu.RUnlock()
		return fmt.Errorf("connection is not connected")
	}
	c.mu.RUnlock()

	select {
	case c.receiveBuffer <- data:
		atomic.AddInt64(&c.MessagesReceived, 1)
		atomic.AddInt64(&c.BytesReceived, int64(len(data)))
		c.updateLastActivity()
		return nil

	default:
		// Buffer is full, apply backpressure policy
		return c.handleBackpressure(data, c.receiveBuffer)
	}
}

// handleBackpressure applies the configured backpressure policy
func (c *MockWebSocketConnection) handleBackpressure(data []byte, buffer chan []byte) error {
	switch c.backpressurePolicy {
	case BackpressureDrop:
		// Drop the oldest message and add the new one
		select {
		case <-buffer:
			atomic.AddInt64(&c.MessagesDropped, 1)
		default:
		}

		select {
		case buffer <- data:
			return nil
		default:
			atomic.AddInt64(&c.MessagesDropped, 1)
			return fmt.Errorf("failed to send message after dropping oldest")
		}

	case BackpressureBlock:
		// Block until buffer has space
		buffer <- data
		return nil

	case BackpressureReject:
		// Reject the message
		atomic.AddInt64(&c.MessagesDropped, 1)
		return fmt.Errorf("message rejected due to full buffer")

	default:
		atomic.AddInt64(&c.MessagesDropped, 1)
		return fmt.Errorf("unknown backpressure policy: %s", c.backpressurePolicy)
	}
}

// processSendBuffer processes messages from the send buffer
func (c *MockWebSocketConnection) processSendBuffer() {
	for {
		select {
		case <-c.sendBuffer:
			// Simulate sending the message (in real implementation, this would go over the network)
			c.updateLastActivity()

		case <-c.closeSignal:
			return
		}
	}
}

// processReceiveBuffer processes messages from the receive buffer
func (c *MockWebSocketConnection) processReceiveBuffer() {
	for {
		select {
		case data := <-c.receiveBuffer:
			// Call the message handler if set
			if c.OnMessage != nil {
				c.OnMessage(data)
			}
			c.updateLastActivity()

		case <-c.closeSignal:
			return
		}
	}
}

// Close closes the WebSocket connection (domain.ManagedConnection interface)
func (c *MockWebSocketConnection) Close(statusCode websocket.StatusCode, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.state = StateDisconnected
	c.closed = true
	close(c.closeSignal)

	if c.OnClose != nil {
		c.OnClose(int(statusCode), reason)
	}

	return nil
}

// CloseWithError closes the WebSocket connection with an error response
func (c *MockWebSocketConnection) CloseWithError(errResp domain.ErrorResponse, reason string) error {
	// In a mock, we'll just close normally but could log the error
	return c.Close(websocket.StatusInternalError, reason)
}

// WriteJSON sends a JSON-encoded message to the client (domain.ManagedConnection interface)
func (c *MockWebSocketConnection) WriteJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return c.SendMessage(data)
}

// RemoteAddr returns the remote network address string (domain.ManagedConnection interface)
func (c *MockWebSocketConnection) RemoteAddr() string {
	return fmt.Sprintf("mock://%s", c.id)
}

// Context returns the context associated with this connection (domain.ManagedConnection interface)
func (c *MockWebSocketConnection) Context() context.Context {
	// Return a background context with the connection ID for testing
	return context.WithValue(context.Background(), "connection_id", c.id)
}

// GetCurrentChatID returns the current chat ID (domain.ManagedConnection interface)
func (c *MockWebSocketConnection) GetCurrentChatID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// For testing, we can use a simple field or derive from other info
	return fmt.Sprintf("chat_%s_%s", c.companyID, c.agentID)
}

// GetState returns the current connection state
func (c *MockWebSocketConnection) GetState() ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// GetMetrics returns current connection metrics
func (c *MockWebSocketConnection) GetMetrics() (sent, received, dropped, bytesSent, bytesReceived int64) {
	return atomic.LoadInt64(&c.MessagesSent),
		atomic.LoadInt64(&c.MessagesReceived),
		atomic.LoadInt64(&c.MessagesDropped),
		atomic.LoadInt64(&c.BytesSent),
		atomic.LoadInt64(&c.BytesReceived)
}

// GetBufferUtilization returns the current buffer utilization percentage
func (c *MockWebSocketConnection) GetBufferUtilization() (sendUtil, receiveUtil float64) {
	sendUtil = float64(len(c.sendBuffer)) / float64(c.bufferSize) * 100
	receiveUtil = float64(len(c.receiveBuffer)) / float64(c.bufferSize) * 100
	return sendUtil, receiveUtil
}

// updateLastActivity updates the last activity timestamp
func (c *MockWebSocketConnection) updateLastActivity() {
	c.mu.Lock()
	c.LastActivity = time.Now()
	c.mu.Unlock()
}

// GetConnectionInfo returns connection metadata
func (c *MockWebSocketConnection) GetConnectionInfo() (id, companyID, agentID, userID string, connectedAt, lastActivity time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.id, c.companyID, c.agentID, c.userID, c.ConnectedAt, c.LastActivity
}

// WebSocketClientPool manages multiple mock WebSocket connections for load testing
type WebSocketClientPool struct {
	connections map[string]*MockWebSocketConnection
	mu          sync.RWMutex

	// Pool metrics
	TotalConnections      int64
	ActiveConnections     int64
	FailedConnections     int64
	TotalMessagesSent     int64
	TotalMessagesReceived int64
	TotalMessagesDropped  int64
}

// NewWebSocketClientPool creates a new WebSocket client pool
func NewWebSocketClientPool() *WebSocketClientPool {
	return &WebSocketClientPool{
		connections: make(map[string]*MockWebSocketConnection),
	}
}

// AddConnection adds a connection to the pool
func (p *WebSocketClientPool) AddConnection(conn *MockWebSocketConnection) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.connections[conn.id] = conn
	atomic.AddInt64(&p.TotalConnections, 1)
	atomic.AddInt64(&p.ActiveConnections, 1)
}

// RemoveConnection removes a connection from the pool
func (p *WebSocketClientPool) RemoveConnection(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, exists := p.connections[id]; exists {
		conn.Close(1000, "removed from pool")
		delete(p.connections, id)
		atomic.AddInt64(&p.ActiveConnections, -1)
	}
}

// GetConnection retrieves a connection by ID
func (p *WebSocketClientPool) GetConnection(id string) (*MockWebSocketConnection, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	conn, exists := p.connections[id]
	return conn, exists
}

// BroadcastMessage sends a message to all connections in the pool
func (p *WebSocketClientPool) BroadcastMessage(data []byte) error {
	p.mu.RLock()
	connections := make([]*MockWebSocketConnection, 0, len(p.connections))
	for _, conn := range p.connections {
		connections = append(connections, conn)
	}
	p.mu.RUnlock()

	var errors []error
	for _, conn := range connections {
		if err := conn.SendMessage(data); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to send to %d connections", len(errors))
	}

	return nil
}

// GetPoolMetrics returns aggregated metrics for all connections
func (p *WebSocketClientPool) GetPoolMetrics() (totalConns, activeConns, failedConns, totalSent, totalReceived, totalDropped int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var sent, received, dropped int64
	for _, conn := range p.connections {
		s, r, d, _, _ := conn.GetMetrics()
		sent += s
		received += r
		dropped += d
	}

	return atomic.LoadInt64(&p.TotalConnections),
		atomic.LoadInt64(&p.ActiveConnections),
		atomic.LoadInt64(&p.FailedConnections),
		sent,
		received,
		dropped
}

// CloseAllConnections closes all connections in the pool
func (p *WebSocketClientPool) CloseAllConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		conn.Close(1000, "pool shutdown")
	}

	p.connections = make(map[string]*MockWebSocketConnection)
	atomic.StoreInt64(&p.ActiveConnections, 0)
}

// GetActiveConnectionCount returns the number of active connections
func (p *WebSocketClientPool) GetActiveConnectionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.connections)
}

// CreateBulkConnections creates multiple connections for load testing
func (p *WebSocketClientPool) CreateBulkConnections(count int, companyID, agentID string, tokens []string, bufferSize int, policy BackpressurePolicy) error {
	if len(tokens) < count {
		return fmt.Errorf("not enough tokens provided: need %d, got %d", count, len(tokens))
	}

	for i := 0; i < count; i++ {
		connID := fmt.Sprintf("conn_%d", i)
		userID := fmt.Sprintf("user_%d", i)
		token := tokens[i]

		conn := NewMockWebSocketConnection(connID, companyID, agentID, userID, token, bufferSize, policy)

		if err := conn.Connect(); err != nil {
			atomic.AddInt64(&p.FailedConnections, 1)
			return fmt.Errorf("failed to connect connection %s: %w", connID, err)
		}

		p.AddConnection(conn)
	}

	return nil
}
