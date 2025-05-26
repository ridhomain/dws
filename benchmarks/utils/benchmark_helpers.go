package utils

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// BenchmarkMetrics tracks performance metrics during benchmarks
type BenchmarkMetrics struct {
	StartTime       time.Time
	EndTime         time.Time
	OperationsCount int64
	ErrorCount      int64
	MemoryStart     runtime.MemStats
	MemoryEnd       runtime.MemStats
	GoroutineStart  int
	GoroutineEnd    int
}

// ServiceMetrics tracks service-specific metrics during benchmarks
type ServiceMetrics struct {
	ActiveConnections      int64
	ConnectionsEstablished int64
	MessagesSent           int64
	MessagesReceived       int64
	AuthSuccesses          int64
	AuthFailures           int64
	SessionLockAttempts    int64
	SessionLockSuccesses   int64
	BufferUtilization      float64
	MessagesDropped        int64
	GRPCForwardAttempts    int64
	GRPCForwardSuccesses   int64
	GRPCForwardFailures    int64
	CircuitBreakerTrips    int64
	TokenCacheHits         int64
	TokenCacheMisses       int64

	mu sync.RWMutex
}

// BenchmarkRunner provides utilities for running benchmarks with metrics collection
type BenchmarkRunner struct {
	startTime      time.Time
	endTime        time.Time
	memStatsStart  runtime.MemStats
	memStatsEnd    runtime.MemStats
	goroutineStart int
	goroutineEnd   int

	// Custom metrics
	operationCount int64
	errorCount     int64

	mu sync.RWMutex
}

// NewBenchmarkRunner creates a new benchmark runner
func NewBenchmarkRunner() *BenchmarkRunner {
	return &BenchmarkRunner{}
}

// Start begins the benchmark measurement
func (br *BenchmarkRunner) Start() {
	br.mu.Lock()
	defer br.mu.Unlock()

	br.startTime = time.Now()
	br.goroutineStart = runtime.NumGoroutine()

	runtime.GC()
	runtime.ReadMemStats(&br.memStatsStart)
}

// Stop ends the benchmark measurement
func (br *BenchmarkRunner) Stop() {
	br.mu.Lock()
	defer br.mu.Unlock()

	br.endTime = time.Now()
	br.goroutineEnd = runtime.NumGoroutine()

	runtime.GC()
	runtime.ReadMemStats(&br.memStatsEnd)
}

// IncrementOperations increments the operation counter
func (br *BenchmarkRunner) IncrementOperations(count int64) {
	atomic.AddInt64(&br.operationCount, count)
}

// IncrementErrors increments the error counter
func (br *BenchmarkRunner) IncrementErrors(count int64) {
	atomic.AddInt64(&br.errorCount, count)
}

// GetResults returns the benchmark results
func (br *BenchmarkRunner) GetResults() *BenchmarkResults {
	br.mu.RLock()
	defer br.mu.RUnlock()

	duration := br.endTime.Sub(br.startTime)
	operations := atomic.LoadInt64(&br.operationCount)
	errors := atomic.LoadInt64(&br.errorCount)

	var opsPerSecond float64
	if duration.Seconds() > 0 {
		opsPerSecond = float64(operations) / duration.Seconds()
	}

	return &BenchmarkResults{
		Duration:            duration,
		Operations:          operations,
		Errors:              errors,
		OperationsPerSecond: opsPerSecond,
		MemoryAllocated:     br.memStatsEnd.TotalAlloc - br.memStatsStart.TotalAlloc,
		MemoryAllocations:   br.memStatsEnd.Mallocs - br.memStatsStart.Mallocs,
		GoroutineStart:      br.goroutineStart,
		GoroutineEnd:        br.goroutineEnd,
		GoroutineLeak:       br.goroutineEnd - br.goroutineStart,
	}
}

// BenchmarkResults holds the results of a benchmark run
type BenchmarkResults struct {
	Duration            time.Duration `json:"duration_ns"`
	Operations          int64         `json:"operations"`
	Errors              int64         `json:"errors"`
	OperationsPerSecond float64       `json:"operations_per_second"`
	MemoryAllocated     uint64        `json:"memory_allocated_bytes"`
	MemoryAllocations   uint64        `json:"memory_allocations"`
	GoroutineStart      int           `json:"goroutine_start"`
	GoroutineEnd        int           `json:"goroutine_end"`
	GoroutineLeak       int           `json:"goroutine_leak"`
}

// String returns a human-readable representation of the results
func (br *BenchmarkResults) String() string {
	return fmt.Sprintf(
		"Duration: %v, Ops: %d, Errors: %d, Ops/sec: %.2f, Memory: %d bytes, Allocs: %d, Goroutines: %d->%d (leak: %d)",
		br.Duration,
		br.Operations,
		br.Errors,
		br.OperationsPerSecond,
		br.MemoryAllocated,
		br.MemoryAllocations,
		br.GoroutineStart,
		br.GoroutineEnd,
		br.GoroutineLeak,
	)
}

// NewServiceMetrics creates a new service metrics tracker
func NewServiceMetrics() *ServiceMetrics {
	return &ServiceMetrics{}
}

// UpdateConnectionMetrics updates connection-related metrics
func (sm *ServiceMetrics) UpdateConnectionMetrics(active, established int64) {
	atomic.StoreInt64(&sm.ActiveConnections, active)
	atomic.AddInt64(&sm.ConnectionsEstablished, established)
}

// UpdateMessageMetrics updates message-related metrics
func (sm *ServiceMetrics) UpdateMessageMetrics(sent, received, dropped int64) {
	atomic.AddInt64(&sm.MessagesSent, sent)
	atomic.AddInt64(&sm.MessagesReceived, received)
	atomic.AddInt64(&sm.MessagesDropped, dropped)
}

// UpdateAuthMetrics updates authentication-related metrics
func (sm *ServiceMetrics) UpdateAuthMetrics(successes, failures int64) {
	atomic.AddInt64(&sm.AuthSuccesses, successes)
	atomic.AddInt64(&sm.AuthFailures, failures)
}

// UpdateSessionMetrics updates session lock-related metrics
func (sm *ServiceMetrics) UpdateSessionMetrics(attempts, successes int64) {
	atomic.AddInt64(&sm.SessionLockAttempts, attempts)
	atomic.AddInt64(&sm.SessionLockSuccesses, successes)
}

// UpdateBufferUtilization updates buffer utilization percentage
func (sm *ServiceMetrics) UpdateBufferUtilization(utilization float64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.BufferUtilization = utilization
}

// UpdateRouteMetrics updates route registry metrics
func (sm *ServiceMetrics) UpdateRouteMetrics(registrations, lookups int64) {
	// For now, we can track these as part of operations
	atomic.AddInt64(&sm.GRPCForwardAttempts, registrations)
	atomic.AddInt64(&sm.GRPCForwardSuccesses, lookups)
}

// UpdateKillSwitchMetrics updates kill switch publishing metrics
func (sm *ServiceMetrics) UpdateKillSwitchMetrics(publishes int64) {
	// Track kill switch publishes as circuit breaker trips
	atomic.AddInt64(&sm.CircuitBreakerTrips, publishes)
}

// GetSnapshot returns a snapshot of current metrics
func (sm *ServiceMetrics) GetSnapshot() ServiceMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return ServiceMetrics{
		ActiveConnections:      atomic.LoadInt64(&sm.ActiveConnections),
		ConnectionsEstablished: atomic.LoadInt64(&sm.ConnectionsEstablished),
		MessagesSent:           atomic.LoadInt64(&sm.MessagesSent),
		MessagesReceived:       atomic.LoadInt64(&sm.MessagesReceived),
		AuthSuccesses:          atomic.LoadInt64(&sm.AuthSuccesses),
		AuthFailures:           atomic.LoadInt64(&sm.AuthFailures),
		SessionLockAttempts:    atomic.LoadInt64(&sm.SessionLockAttempts),
		SessionLockSuccesses:   atomic.LoadInt64(&sm.SessionLockSuccesses),
		BufferUtilization:      sm.BufferUtilization,
		MessagesDropped:        atomic.LoadInt64(&sm.MessagesDropped),
	}
}

// EventPayloadGenerator creates test NATS event payloads
type EventPayloadGenerator struct {
	eventCounter int64
}

// NewEventPayloadGenerator creates a new event payload generator
func NewEventPayloadGenerator() *EventPayloadGenerator {
	return &EventPayloadGenerator{}
}

// GenerateChatEvent creates a chat event payload
func (epg *EventPayloadGenerator) GenerateChatEvent(companyID, agentID, chatID string) *domain.EnrichedEventPayload {
	eventID := atomic.AddInt64(&epg.eventCounter, 1)

	return &domain.EnrichedEventPayload{
		EventID:   fmt.Sprintf("chat_event_%d", eventID),
		EventTime: time.Now().Format(time.RFC3339),
		CompanyID: companyID,
		AgentID:   agentID,
		ChatID:    chatID,
		RowData: map[string]interface{}{
			"id":         chatID,
			"company_id": companyID,
			"agent_id":   agentID,
			"status":     "active",
			"created_at": time.Now().Format(time.RFC3339),
		},
	}
}

// GenerateMessageEvent creates a message event payload
func (epg *EventPayloadGenerator) GenerateMessageEvent(companyID, agentID, chatID, messageID string) *domain.EnrichedEventPayload {
	eventID := atomic.AddInt64(&epg.eventCounter, 1)

	return &domain.EnrichedEventPayload{
		EventID:   fmt.Sprintf("message_event_%d", eventID),
		EventTime: time.Now().Format(time.RFC3339),
		CompanyID: companyID,
		AgentID:   agentID,
		ChatID:    chatID,
		MessageID: messageID,
		RowData: map[string]interface{}{
			"id":         messageID,
			"chat_id":    chatID,
			"company_id": companyID,
			"agent_id":   agentID,
			"content":    fmt.Sprintf("Test message %d", eventID),
			"created_at": time.Now().Format(time.RFC3339),
		},
	}
}

// GenerateAgentEvent creates an agent event payload
func (epg *EventPayloadGenerator) GenerateAgentEvent(companyID, agentID string) *domain.EnrichedEventPayload {
	eventID := atomic.AddInt64(&epg.eventCounter, 1)

	return &domain.EnrichedEventPayload{
		EventID:   fmt.Sprintf("agent_event_%d", eventID),
		EventTime: time.Now().Format(time.RFC3339),
		CompanyID: companyID,
		AgentID:   agentID,
		RowData: map[string]interface{}{
			"id":         agentID,
			"company_id": companyID,
			"name":       fmt.Sprintf("Agent %s", agentID),
			"status":     "online",
			"updated_at": time.Now().Format(time.RFC3339),
		},
	}
}

// GenerateBulkEvents creates multiple events for load testing
func (epg *EventPayloadGenerator) GenerateBulkEvents(count int, companyID, agentID string) []*domain.EnrichedEventPayload {
	events := make([]*domain.EnrichedEventPayload, count)

	for i := 0; i < count; i++ {
		chatID := fmt.Sprintf("chat_%d", i%10) // Distribute across 10 chats
		messageID := fmt.Sprintf("msg_%d", i)

		if i%3 == 0 {
			events[i] = epg.GenerateChatEvent(companyID, agentID, chatID)
		} else if i%3 == 1 {
			events[i] = epg.GenerateMessageEvent(companyID, agentID, chatID, messageID)
		} else {
			events[i] = epg.GenerateAgentEvent(companyID, agentID)
		}
	}

	return events
}

// SerializeEvent converts an event to JSON for NATS simulation
func (epg *EventPayloadGenerator) SerializeEvent(event *domain.EnrichedEventPayload) ([]byte, error) {
	return json.Marshal(event)
}

// ConcurrentTestRunner manages concurrent load testing
type ConcurrentTestRunner struct {
	workerCount int
	duration    time.Duration
	results     chan *BenchmarkResults
	errors      chan error
	stopSignal  chan struct{}

	mu sync.RWMutex
}

// NewConcurrentTestRunner creates a new concurrent test runner
func NewConcurrentTestRunner(workerCount int, duration time.Duration) *ConcurrentTestRunner {
	return &ConcurrentTestRunner{
		workerCount: workerCount,
		duration:    duration,
		results:     make(chan *BenchmarkResults, workerCount),
		errors:      make(chan error, workerCount*10),
		stopSignal:  make(chan struct{}),
	}
}

// RunTest executes a concurrent test with the provided worker function
func (ctr *ConcurrentTestRunner) RunTest(workerFunc func(workerID int, stopSignal <-chan struct{}) *BenchmarkResults) ([]*BenchmarkResults, []error) {
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < ctr.workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			result := workerFunc(workerID, ctr.stopSignal)
			if result != nil {
				ctr.results <- result
			}
		}(i)
	}

	// Stop workers after duration
	go func() {
		time.Sleep(ctr.duration)
		close(ctr.stopSignal)
	}()

	// Wait for all workers to complete
	wg.Wait()
	close(ctr.results)
	close(ctr.errors)

	// Collect results
	var results []*BenchmarkResults
	var errors []error

	for result := range ctr.results {
		results = append(results, result)
	}

	for err := range ctr.errors {
		errors = append(errors, err)
	}

	return results, errors
}

// LoadProfile defines different load testing scenarios
type LoadProfile struct {
	Name            string
	ConcurrentUsers int
	Duration        time.Duration
	RampUpTime      time.Duration
	MessageRate     int // messages per second per user
}

// PredefinedLoadProfiles provides common load testing scenarios
var PredefinedLoadProfiles = map[string]LoadProfile{
	"light": {
		Name:            "Light Load",
		ConcurrentUsers: 10,
		Duration:        30 * time.Second,
		RampUpTime:      5 * time.Second,
		MessageRate:     1,
	},
	"medium": {
		Name:            "Medium Load",
		ConcurrentUsers: 100,
		Duration:        60 * time.Second,
		RampUpTime:      10 * time.Second,
		MessageRate:     2,
	},
	"heavy": {
		Name:            "Heavy Load",
		ConcurrentUsers: 1000,
		Duration:        120 * time.Second,
		RampUpTime:      20 * time.Second,
		MessageRate:     5,
	},
	"stress": {
		Name:            "Stress Test",
		ConcurrentUsers: 5000,
		Duration:        300 * time.Second,
		RampUpTime:      60 * time.Second,
		MessageRate:     10,
	},
}

// BenchmarkReport aggregates multiple benchmark results
type BenchmarkReport struct {
	TestName        string                    `json:"test_name"`
	StartTime       time.Time                 `json:"start_time"`
	EndTime         time.Time                 `json:"end_time"`
	LoadProfile     LoadProfile               `json:"load_profile"`
	Results         []*BenchmarkResults       `json:"results"`
	AggregatedStats *AggregatedBenchmarkStats `json:"aggregated_stats"`
	ServiceMetrics  ServiceMetrics            `json:"service_metrics"`
	Errors          []string                  `json:"errors"`
}

// AggregatedBenchmarkStats provides summary statistics
type AggregatedBenchmarkStats struct {
	TotalOperations      int64         `json:"total_operations"`
	TotalErrors          int64         `json:"total_errors"`
	AverageOpsPerSecond  float64       `json:"average_ops_per_second"`
	MaxOpsPerSecond      float64       `json:"max_ops_per_second"`
	MinOpsPerSecond      float64       `json:"min_ops_per_second"`
	TotalMemoryAllocated uint64        `json:"total_memory_allocated"`
	AverageDuration      time.Duration `json:"average_duration"`
	MaxGoroutineLeak     int           `json:"max_goroutine_leak"`
	ErrorRate            float64       `json:"error_rate"`
}

// GenerateReport creates a comprehensive benchmark report
func GenerateReport(testName string, loadProfile LoadProfile, results []*BenchmarkResults, serviceMetrics ServiceMetrics, errors []error) *BenchmarkReport {
	report := &BenchmarkReport{
		TestName:       testName,
		StartTime:      time.Now(),
		EndTime:        time.Now(),
		LoadProfile:    loadProfile,
		Results:        results,
		ServiceMetrics: serviceMetrics,
		Errors:         make([]string, len(errors)),
	}

	// Convert errors to strings
	for i, err := range errors {
		report.Errors[i] = err.Error()
	}

	// Calculate aggregated statistics
	if len(results) > 0 {
		stats := &AggregatedBenchmarkStats{}

		var totalDuration time.Duration
		var maxOps, minOps float64 = 0, float64(^uint64(0) >> 1) // max float64
		var maxLeak int

		for _, result := range results {
			stats.TotalOperations += result.Operations
			stats.TotalErrors += result.Errors
			stats.TotalMemoryAllocated += result.MemoryAllocated
			totalDuration += result.Duration

			if result.OperationsPerSecond > maxOps {
				maxOps = result.OperationsPerSecond
			}
			if result.OperationsPerSecond < minOps && result.OperationsPerSecond > 0 {
				minOps = result.OperationsPerSecond
			}
			if result.GoroutineLeak > maxLeak {
				maxLeak = result.GoroutineLeak
			}
		}

		stats.AverageOpsPerSecond = maxOps / float64(len(results))
		stats.MaxOpsPerSecond = maxOps
		stats.MinOpsPerSecond = minOps
		stats.AverageDuration = totalDuration / time.Duration(len(results))
		stats.MaxGoroutineLeak = maxLeak

		if stats.TotalOperations > 0 {
			stats.ErrorRate = float64(stats.TotalErrors) / float64(stats.TotalOperations) * 100
		}

		report.AggregatedStats = stats
	}

	return report
}

// SaveReportToJSON saves the benchmark report as JSON
func (br *BenchmarkReport) SaveReportToJSON(filename string) error {
	data, err := json.MarshalIndent(br, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	// In a real implementation, you would write to a file
	// For now, we'll just return the JSON as a string in the error for testing
	_ = data
	return nil
}

// PrintSummary prints a human-readable summary of the report
func (br *BenchmarkReport) PrintSummary() string {
	if br.AggregatedStats == nil {
		return "No aggregated statistics available"
	}

	return fmt.Sprintf(`
Benchmark Report: %s
===================
Load Profile: %s
Duration: %v
Workers: %d

Results:
- Total Operations: %d
- Total Errors: %d
- Error Rate: %.2f%%
- Average Ops/sec: %.2f
- Max Ops/sec: %.2f
- Min Ops/sec: %.2f
- Total Memory: %d bytes
- Max Goroutine Leak: %d

Service Metrics:
- Active Connections: %d
- Messages Sent: %d
- Messages Received: %d
- Auth Successes: %d
- Auth Failures: %d
- Buffer Utilization: %.2f%%
`,
		br.TestName,
		br.LoadProfile.Name,
		br.LoadProfile.Duration,
		br.LoadProfile.ConcurrentUsers,
		br.AggregatedStats.TotalOperations,
		br.AggregatedStats.TotalErrors,
		br.AggregatedStats.ErrorRate,
		br.AggregatedStats.AverageOpsPerSecond,
		br.AggregatedStats.MaxOpsPerSecond,
		br.AggregatedStats.MinOpsPerSecond,
		br.AggregatedStats.TotalMemoryAllocated,
		br.AggregatedStats.MaxGoroutineLeak,
		br.ServiceMetrics.ActiveConnections,
		br.ServiceMetrics.MessagesSent,
		br.ServiceMetrics.MessagesReceived,
		br.ServiceMetrics.AuthSuccesses,
		br.ServiceMetrics.AuthFailures,
		br.ServiceMetrics.BufferUtilization,
	)
}
