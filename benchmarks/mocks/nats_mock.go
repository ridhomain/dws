package mocks

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/nats-io/nats.go"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// MockMessage represents a mock NATS message for testing
type MockMessage struct {
	Subject string
	Data    []byte
	Header  nats.Header
	Reply   string
}

// MockNatsSubscription implements domain.NatsMessageSubscription
type MockNatsSubscription struct {
	subject string
	isValid bool
	drained bool
	mu      sync.RWMutex
}

func (m *MockNatsSubscription) Drain() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drained = true
	m.isValid = false
	return nil
}

func (m *MockNatsSubscription) IsValid() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isValid
}

func (m *MockNatsSubscription) Subject() string {
	return m.subject
}

// MockNatsConsumer implements domain.NatsConsumer for benchmarking
type MockNatsConsumer struct {
	handlers      map[string]domain.NatsMessageHandler
	subscriptions map[string]*MockNatsSubscription
	messageQueue  chan *MockMessage
	mu            sync.RWMutex

	// Metrics for benchmarking
	SubscriptionCount int64
	MessagesProcessed int64
	HandlerCallCount  int64
}

// NewMockNatsConsumer creates a new mock NATS consumer
func NewMockNatsConsumer() *MockNatsConsumer {
	return &MockNatsConsumer{
		handlers:      make(map[string]domain.NatsMessageHandler),
		subscriptions: make(map[string]*MockNatsSubscription),
		messageQueue:  make(chan *MockMessage, 1000), // Buffered for performance
	}
}

// SubscribeToChats implements domain.NatsConsumer
func (m *MockNatsConsumer) SubscribeToChats(ctx context.Context, companyID, agentID string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	subject := "chats." + companyID + "." + agentID
	return m.subscribe(subject, handler)
}

// SubscribeToChatMessages implements domain.NatsConsumer
func (m *MockNatsConsumer) SubscribeToChatMessages(ctx context.Context, companyID, agentID, chatID string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	subject := "messages." + companyID + "." + agentID + "." + chatID
	return m.subscribe(subject, handler)
}

// SubscribeToAgentEvents implements domain.NatsConsumer
func (m *MockNatsConsumer) SubscribeToAgentEvents(ctx context.Context, companyIDPattern, agentIDPattern string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	subject := "agents." + companyIDPattern + "." + agentIDPattern
	return m.subscribe(subject, handler)
}

// subscribe is a helper method to register subscriptions
func (m *MockNatsConsumer) subscribe(subject string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	atomic.AddInt64(&m.SubscriptionCount, 1)

	subscription := &MockNatsSubscription{
		subject: subject,
		isValid: true,
	}

	m.handlers[subject] = handler
	m.subscriptions[subject] = subscription

	return subscription, nil
}

// NatsConn implements domain.NatsConsumer
func (m *MockNatsConsumer) NatsConn() *nats.Conn {
	// Return nil for mock - benchmarks shouldn't need the actual connection
	return nil
}

// Close implements domain.NatsConsumer
func (m *MockNatsConsumer) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, sub := range m.subscriptions {
		sub.Drain()
	}

	close(m.messageQueue)
}

// InjectMessage simulates receiving a NATS message for a specific subject
func (m *MockNatsConsumer) InjectMessage(subject string, data []byte) {
	m.mu.RLock()
	handler, exists := m.handlers[subject]
	m.mu.RUnlock()

	if exists {
		atomic.AddInt64(&m.MessagesProcessed, 1)
		atomic.AddInt64(&m.HandlerCallCount, 1)

		// Create a mock NATS message
		msg := &nats.Msg{
			Subject: subject,
			Data:    data,
		}

		handler(msg)
	}
}

// SimulateMessageBurst sends multiple messages rapidly for load testing
func (m *MockNatsConsumer) SimulateMessageBurst(subject string, messages [][]byte) {
	for _, data := range messages {
		m.InjectMessage(subject, data)
	}
}

// GetMetrics returns current metrics for benchmark analysis
func (m *MockNatsConsumer) GetMetrics() (subscriptions, processed, handlerCalls int64) {
	return atomic.LoadInt64(&m.SubscriptionCount),
		atomic.LoadInt64(&m.MessagesProcessed),
		atomic.LoadInt64(&m.HandlerCallCount)
}

// Reset clears all metrics and state for test reuse
func (m *MockNatsConsumer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	atomic.StoreInt64(&m.SubscriptionCount, 0)
	atomic.StoreInt64(&m.MessagesProcessed, 0)
	atomic.StoreInt64(&m.HandlerCallCount, 0)

	m.handlers = make(map[string]domain.NatsMessageHandler)
	m.subscriptions = make(map[string]*MockNatsSubscription)

	// Drain and recreate message queue
	select {
	case <-m.messageQueue:
	default:
	}
	m.messageQueue = make(chan *MockMessage, 1000)
}
