package mocks

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// ForwardedMessage represents a message that was forwarded for testing
type ForwardedMessage struct {
	TargetPodAddress string
	Event            *domain.EnrichedEventPayload
	TargetCompanyID  string
	TargetAgentID    string
	TargetChatID     string
	SourcePodID      string
	Timestamp        time.Time
}

// MockMessageForwarder implements domain.MessageForwarder for benchmarking
type MockMessageForwarder struct {
	forwardedEvents []forwardedEvent
	failures        map[string]int  // podAddress -> failure count
	circuitBreaker  map[string]bool // podAddress -> is circuit open
	mu              sync.RWMutex

	// Configuration for failure simulation
	FailureRate      float64 // 0.0 to 1.0, probability of failure
	CircuitThreshold int     // Number of failures before circuit opens

	// Metrics
	ForwardAttempts  int64
	ForwardSuccesses int64
	ForwardFailures  int64
	CircuitOpens     int64
}

type forwardedEvent struct {
	TargetPodAddress string
	Event            *domain.EnrichedEventPayload
	TargetCompanyID  string
	TargetAgentID    string
	TargetChatID     string
	SourcePodID      string
	Timestamp        time.Time
	Success          bool
	Error            error
}

// NewMockMessageForwarder creates a new mock message forwarder
func NewMockMessageForwarder() *MockMessageForwarder {
	return &MockMessageForwarder{
		forwardedEvents:  make([]forwardedEvent, 0),
		failures:         make(map[string]int),
		circuitBreaker:   make(map[string]bool),
		FailureRate:      0.0, // Default: no failures
		CircuitThreshold: 5,   // Default: 5 failures before circuit opens
	}
}

// ForwardEvent implements domain.MessageForwarder
func (m *MockMessageForwarder) ForwardEvent(ctx context.Context, targetPodAddress string, event *domain.EnrichedEventPayload, targetCompanyID, targetAgentID, targetChatID, sourcePodID string) error {
	atomic.AddInt64(&m.ForwardAttempts, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if circuit breaker is open
	if m.circuitBreaker[targetPodAddress] {
		forwardEvent := forwardedEvent{
			TargetPodAddress: targetPodAddress,
			Event:            event,
			TargetCompanyID:  targetCompanyID,
			TargetAgentID:    targetAgentID,
			TargetChatID:     targetChatID,
			SourcePodID:      sourcePodID,
			Timestamp:        time.Now(),
			Success:          false,
			Error:            &CircuitBreakerOpenError{PodAddress: targetPodAddress},
		}
		m.forwardedEvents = append(m.forwardedEvents, forwardEvent)
		atomic.AddInt64(&m.ForwardFailures, 1)
		return forwardEvent.Error
	}

	// Simulate failure based on failure rate
	shouldFail := m.shouldSimulateFailure()

	var err error
	success := !shouldFail

	if shouldFail {
		m.failures[targetPodAddress]++
		err = &ForwardingError{
			PodAddress: targetPodAddress,
			Message:    "simulated forwarding failure",
		}

		// Check if we should open circuit breaker
		if m.failures[targetPodAddress] >= m.CircuitThreshold {
			m.circuitBreaker[targetPodAddress] = true
			atomic.AddInt64(&m.CircuitOpens, 1)
		}

		atomic.AddInt64(&m.ForwardFailures, 1)
	} else {
		// Reset failure count on success
		m.failures[targetPodAddress] = 0
		atomic.AddInt64(&m.ForwardSuccesses, 1)
	}

	// Record the forwarding attempt
	forwardEvent := forwardedEvent{
		TargetPodAddress: targetPodAddress,
		Event:            event,
		TargetCompanyID:  targetCompanyID,
		TargetAgentID:    targetAgentID,
		TargetChatID:     targetChatID,
		SourcePodID:      sourcePodID,
		Timestamp:        time.Now(),
		Success:          success,
		Error:            err,
	}

	m.forwardedEvents = append(m.forwardedEvents, forwardEvent)

	return err
}

// shouldSimulateFailure determines if this call should fail based on failure rate
func (m *MockMessageForwarder) shouldSimulateFailure() bool {
	if m.FailureRate <= 0.0 {
		return false
	}
	if m.FailureRate >= 1.0 {
		return true
	}

	// Simple pseudo-random failure simulation
	// In a real implementation, you might use a proper random number generator
	return time.Now().UnixNano()%100 < int64(m.FailureRate*100)
}

// GetForwardedEvents returns all forwarded events for testing
func (m *MockMessageForwarder) GetForwardedEvents() []forwardedEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid race conditions
	events := make([]forwardedEvent, len(m.forwardedEvents))
	copy(events, m.forwardedEvents)
	return events
}

// GetCircuitBreakerStatus returns the circuit breaker status for all pods
func (m *MockMessageForwarder) GetCircuitBreakerStatus() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]bool)
	for pod, isOpen := range m.circuitBreaker {
		status[pod] = isOpen
	}
	return status
}

// GetMetrics returns current metrics for benchmark analysis
func (m *MockMessageForwarder) GetMetrics() (attempts, successes, failures, circuitOpens int64) {
	return atomic.LoadInt64(&m.ForwardAttempts),
		atomic.LoadInt64(&m.ForwardSuccesses),
		atomic.LoadInt64(&m.ForwardFailures),
		atomic.LoadInt64(&m.CircuitOpens)
}

// Reset clears all state and metrics
func (m *MockMessageForwarder) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.forwardedEvents = make([]forwardedEvent, 0)
	m.failures = make(map[string]int)
	m.circuitBreaker = make(map[string]bool)

	atomic.StoreInt64(&m.ForwardAttempts, 0)
	atomic.StoreInt64(&m.ForwardSuccesses, 0)
	atomic.StoreInt64(&m.ForwardFailures, 0)
	atomic.StoreInt64(&m.CircuitOpens, 0)
}

// Custom error types for simulation

type CircuitBreakerOpenError struct {
	PodAddress string
}

func (e *CircuitBreakerOpenError) Error() string {
	return "circuit breaker is open for pod: " + e.PodAddress
}

type ForwardingError struct {
	PodAddress string
	Message    string
}

func (e *ForwardingError) Error() string {
	return "forwarding failed to " + e.PodAddress + ": " + e.Message
}

// MockLogger implements domain.Logger for benchmarking
type MockLogger struct {
	logEntries []logEntry
	mu         sync.RWMutex

	// Metrics
	InfoCount  int64
	WarnCount  int64
	ErrorCount int64
	DebugCount int64
}

type logEntry struct {
	Level     string
	Message   string
	Fields    map[string]interface{}
	Timestamp time.Time
}

// NewMockLogger creates a new mock logger
func NewMockLogger() *MockLogger {
	return &MockLogger{
		logEntries: make([]logEntry, 0),
	}
}

// Info implements domain.Logger
func (m *MockLogger) Info(ctx context.Context, msg string, fields ...any) {
	atomic.AddInt64(&m.InfoCount, 1)
	m.addLogEntry("INFO", msg, fields...)
}

// Warn implements domain.Logger
func (m *MockLogger) Warn(ctx context.Context, msg string, fields ...any) {
	atomic.AddInt64(&m.WarnCount, 1)
	m.addLogEntry("WARN", msg, fields...)
}

// Error implements domain.Logger
func (m *MockLogger) Error(ctx context.Context, msg string, fields ...any) {
	atomic.AddInt64(&m.ErrorCount, 1)
	m.addLogEntry("ERROR", msg, fields...)
}

// Debug implements domain.Logger
func (m *MockLogger) Debug(ctx context.Context, msg string, fields ...any) {
	atomic.AddInt64(&m.DebugCount, 1)
	m.addLogEntry("DEBUG", msg, fields...)
}

// Fatal implements domain.Logger
func (m *MockLogger) Fatal(ctx context.Context, msg string, fields ...any) {
	atomic.AddInt64(&m.ErrorCount, 1)
	m.addLogEntry("FATAL", msg, fields...)
}

// With implements domain.Logger
func (m *MockLogger) With(fields ...any) domain.Logger {
	// Return a new logger with additional fields (simplified implementation)
	return m
}

// addLogEntry is a helper method to record log entries
func (m *MockLogger) addLogEntry(level, msg string, fields ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fieldMap := make(map[string]interface{})
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok && i+1 < len(fields) {
			fieldMap[key] = fields[i+1]
		}
	}

	entry := logEntry{
		Level:     level,
		Message:   msg,
		Fields:    fieldMap,
		Timestamp: time.Now(),
	}

	m.logEntries = append(m.logEntries, entry)
}

// GetLogEntries returns all log entries for testing
func (m *MockLogger) GetLogEntries() []logEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to avoid race conditions
	entries := make([]logEntry, len(m.logEntries))
	copy(entries, m.logEntries)
	return entries
}

// GetLogEntriesByLevel returns log entries filtered by level
func (m *MockLogger) GetLogEntriesByLevel(level string) []logEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var filtered []logEntry
	for _, entry := range m.logEntries {
		if entry.Level == level {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// GetMetrics returns current metrics for benchmark analysis
func (m *MockLogger) GetMetrics() (info, warn, error, debug int64) {
	return atomic.LoadInt64(&m.InfoCount),
		atomic.LoadInt64(&m.WarnCount),
		atomic.LoadInt64(&m.ErrorCount),
		atomic.LoadInt64(&m.DebugCount)
}

// Reset clears all log entries and metrics
func (m *MockLogger) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logEntries = make([]logEntry, 0)

	atomic.StoreInt64(&m.InfoCount, 0)
	atomic.StoreInt64(&m.WarnCount, 0)
	atomic.StoreInt64(&m.ErrorCount, 0)
	atomic.StoreInt64(&m.DebugCount, 0)
}
