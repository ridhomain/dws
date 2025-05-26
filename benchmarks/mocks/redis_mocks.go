package mocks

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// MockSessionLockManager implements domain.SessionLockManager for benchmarking
type MockSessionLockManager struct {
	locks      map[string]lockEntry
	activities map[string]time.Time
	mu         sync.RWMutex

	// Metrics for benchmarking
	LockAttempts     int64
	LockSuccesses    int64
	LockFailures     int64
	RefreshAttempts  int64
	RefreshSuccesses int64
	ReleaseAttempts  int64
	ReleaseSuccesses int64
}

type lockEntry struct {
	value     string
	expiresAt time.Time
}

// NewMockSessionLockManager creates a new mock session lock manager
func NewMockSessionLockManager() *MockSessionLockManager {
	return &MockSessionLockManager{
		locks:      make(map[string]lockEntry),
		activities: make(map[string]time.Time),
	}
}

// AcquireLock implements domain.SessionLockManager
func (m *MockSessionLockManager) AcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	atomic.AddInt64(&m.LockAttempts, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Check if lock exists and is not expired
	if entry, exists := m.locks[key]; exists && now.Before(entry.expiresAt) {
		atomic.AddInt64(&m.LockFailures, 1)
		return false, nil
	}

	// Acquire the lock
	m.locks[key] = lockEntry{
		value:     value,
		expiresAt: now.Add(ttl),
	}

	atomic.AddInt64(&m.LockSuccesses, 1)
	return true, nil
}

// ReleaseLock implements domain.SessionLockManager
func (m *MockSessionLockManager) ReleaseLock(ctx context.Context, key string, value string) (bool, error) {
	atomic.AddInt64(&m.ReleaseAttempts, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.locks[key]
	if !exists || entry.value != value {
		return false, nil
	}

	delete(m.locks, key)
	atomic.AddInt64(&m.ReleaseSuccesses, 1)
	return true, nil
}

// RefreshLock implements domain.SessionLockManager
func (m *MockSessionLockManager) RefreshLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	atomic.AddInt64(&m.RefreshAttempts, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.locks[key]
	if !exists || entry.value != value {
		return false, nil
	}

	// Refresh the lock
	m.locks[key] = lockEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	atomic.AddInt64(&m.RefreshSuccesses, 1)
	return true, nil
}

// ForceAcquireLock implements domain.SessionLockManager
func (m *MockSessionLockManager) ForceAcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	atomic.AddInt64(&m.LockAttempts, 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Force acquire always succeeds
	m.locks[key] = lockEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	atomic.AddInt64(&m.LockSuccesses, 1)
	return true, nil
}

// RecordActivity implements domain.SessionLockManager
func (m *MockSessionLockManager) RecordActivity(ctx context.Context, key string, activityTTL time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activities[key] = time.Now().Add(activityTTL)
	return nil
}

// GetMetrics returns current metrics for benchmark analysis
func (m *MockSessionLockManager) GetMetrics() (attempts, successes, failures, refreshAttempts, refreshSuccesses, releaseAttempts, releaseSuccesses int64) {
	return atomic.LoadInt64(&m.LockAttempts),
		atomic.LoadInt64(&m.LockSuccesses),
		atomic.LoadInt64(&m.LockFailures),
		atomic.LoadInt64(&m.RefreshAttempts),
		atomic.LoadInt64(&m.RefreshSuccesses),
		atomic.LoadInt64(&m.ReleaseAttempts),
		atomic.LoadInt64(&m.ReleaseSuccesses)
}

// Reset clears all state and metrics
func (m *MockSessionLockManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.locks = make(map[string]lockEntry)
	m.activities = make(map[string]time.Time)

	atomic.StoreInt64(&m.LockAttempts, 0)
	atomic.StoreInt64(&m.LockSuccesses, 0)
	atomic.StoreInt64(&m.LockFailures, 0)
	atomic.StoreInt64(&m.RefreshAttempts, 0)
	atomic.StoreInt64(&m.RefreshSuccesses, 0)
	atomic.StoreInt64(&m.ReleaseAttempts, 0)
	atomic.StoreInt64(&m.ReleaseSuccesses, 0)
}

// MockRouteRegistry implements domain.RouteRegistry using in-memory storage
type MockRouteRegistry struct {
	routes   map[string]map[string]bool // routeKey -> set of podIDs
	activity map[string]time.Time       // routeKey -> last activity
	mu       sync.RWMutex

	// Metrics for benchmarking
	RegistrationCount   int64
	UnregistrationCount int64
	LookupCount         int64
	RefreshCount        int64
}

// NewMockRouteRegistry creates a new mock route registry
func NewMockRouteRegistry() *MockRouteRegistry {
	return &MockRouteRegistry{
		routes:   make(map[string]map[string]bool),
		activity: make(map[string]time.Time),
	}
}

// RegisterChatRoute implements domain.RouteRegistry
func (m *MockRouteRegistry) RegisterChatRoute(ctx context.Context, companyID, agentID, podID string, ttl time.Duration) error {
	routeKey := fmt.Sprintf("route:%s:%s:chats", companyID, agentID)
	return m.registerRoute(routeKey, podID)
}

// UnregisterChatRoute implements domain.RouteRegistry
func (m *MockRouteRegistry) UnregisterChatRoute(ctx context.Context, companyID, agentID, podID string) error {
	routeKey := fmt.Sprintf("route:%s:%s:chats", companyID, agentID)
	return m.unregisterRoute(routeKey, podID)
}

// RegisterMessageRoute implements domain.RouteRegistry
func (m *MockRouteRegistry) RegisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string, ttl time.Duration) error {
	routeKey := fmt.Sprintf("route:%s:%s:messages:%s", companyID, agentID, chatID)
	return m.registerRoute(routeKey, podID)
}

// UnregisterMessageRoute implements domain.RouteRegistry
func (m *MockRouteRegistry) UnregisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string) error {
	routeKey := fmt.Sprintf("route:%s:%s:messages:%s", companyID, agentID, chatID)
	return m.unregisterRoute(routeKey, podID)
}

// GetOwningPodForMessageRoute implements domain.RouteRegistry
func (m *MockRouteRegistry) GetOwningPodForMessageRoute(ctx context.Context, companyID, agentID, chatID string) (string, error) {
	routeKey := fmt.Sprintf("route:%s:%s:messages:%s", companyID, agentID, chatID)

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.LookupCount++

	pods, exists := m.routes[routeKey]
	if !exists || len(pods) == 0 {
		return "", fmt.Errorf("no pod owns route %s", routeKey)
	}

	// Return the first pod (in real Redis, this would be a single member)
	for podID := range pods {
		return podID, nil
	}

	return "", fmt.Errorf("no pod owns route %s", routeKey)
}

// GetOwningPodsForChatRoute implements domain.RouteRegistry
func (m *MockRouteRegistry) GetOwningPodsForChatRoute(ctx context.Context, companyID, agentID string) ([]string, error) {
	routeKey := fmt.Sprintf("route:%s:%s:chats", companyID, agentID)

	m.mu.RLock()
	defer m.mu.RUnlock()

	m.LookupCount++

	pods, exists := m.routes[routeKey]
	if !exists {
		return []string{}, nil
	}

	var podList []string
	for podID := range pods {
		podList = append(podList, podID)
	}

	return podList, nil
}

// RefreshRouteTTL implements domain.RouteRegistry
func (m *MockRouteRegistry) RefreshRouteTTL(ctx context.Context, routeKey, podID string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RefreshCount++

	pods, exists := m.routes[routeKey]
	if !exists {
		return false, nil
	}

	if !pods[podID] {
		return false, nil // Pod is not in the route
	}

	// In a real implementation, this would refresh the TTL in Redis
	// For the mock, we just record the activity
	m.activity[routeKey] = time.Now()
	return true, nil
}

// RecordActivity implements domain.RouteRegistry
func (m *MockRouteRegistry) RecordActivity(ctx context.Context, routeKey string, activityTTL time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activity[routeKey] = time.Now()
	return nil
}

// registerRoute is a helper method
func (m *MockRouteRegistry) registerRoute(routeKey, podID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RegistrationCount++

	if m.routes[routeKey] == nil {
		m.routes[routeKey] = make(map[string]bool)
	}

	m.routes[routeKey][podID] = true
	m.activity[routeKey] = time.Now()

	return nil
}

// unregisterRoute is a helper method
func (m *MockRouteRegistry) unregisterRoute(routeKey, podID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.UnregistrationCount++

	pods, exists := m.routes[routeKey]
	if !exists {
		return nil // Route doesn't exist
	}

	delete(pods, podID)

	// Clean up empty routes
	if len(pods) == 0 {
		delete(m.routes, routeKey)
		delete(m.activity, routeKey)
	}

	return nil
}

// GetAllRoutes returns all routes for testing purposes
func (m *MockRouteRegistry) GetAllRoutes() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]string)
	for routeKey, pods := range m.routes {
		var podList []string
		for podID := range pods {
			podList = append(podList, podID)
		}
		result[routeKey] = podList
	}

	return result
}

// Reset clears all routes for reuse in tests
func (m *MockRouteRegistry) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.routes = make(map[string]map[string]bool)
	m.activity = make(map[string]time.Time)
	m.RegistrationCount = 0
	m.UnregistrationCount = 0
	m.LookupCount = 0
	m.RefreshCount = 0
}

// CacheItem represents a cached item with expiration
type CacheItem struct {
	Value     interface{}
	ExpiresAt time.Time
}

// MockTokenCacheStore implements domain.TokenCacheStore using in-memory storage
type MockTokenCacheStore struct {
	cache map[string]CacheItem
	mu    sync.RWMutex

	// Metrics for benchmarking
	Hits   int64
	Misses int64
	Sets   int64
}

// NewMockTokenCacheStore creates a new mock token cache store
func NewMockTokenCacheStore() *MockTokenCacheStore {
	return &MockTokenCacheStore{
		cache: make(map[string]CacheItem),
	}
}

// Get implements domain.TokenCacheStore
func (m *MockTokenCacheStore) Get(ctx context.Context, key string) (*domain.AuthenticatedUserContext, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.cache[key]
	if !exists {
		m.Misses++
		return nil, nil
	}

	// Check if expired
	if time.Now().After(item.ExpiresAt) {
		m.Misses++
		return nil, nil
	}

	m.Hits++
	if userCtx, ok := item.Value.(*domain.AuthenticatedUserContext); ok {
		return userCtx, nil
	}

	return nil, fmt.Errorf("invalid type in cache")
}

// Set implements domain.TokenCacheStore
func (m *MockTokenCacheStore) Set(ctx context.Context, key string, value *domain.AuthenticatedUserContext, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Sets++
	m.cache[key] = CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}

	return nil
}

// GetHitRatio returns the cache hit ratio for benchmarking
func (m *MockTokenCacheStore) GetHitRatio() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := m.Hits + m.Misses
	if total == 0 {
		return 0.0
	}
	return float64(m.Hits) / float64(total)
}

// Reset clears all cache for reuse in tests
func (m *MockTokenCacheStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache = make(map[string]CacheItem)
	m.Hits = 0
	m.Misses = 0
	m.Sets = 0
}

// MockAdminTokenCacheStore implements domain.AdminTokenCacheStore using in-memory storage
type MockAdminTokenCacheStore struct {
	cache map[string]CacheItem
	mu    sync.RWMutex

	// Metrics for benchmarking
	Hits   int64
	Misses int64
	Sets   int64
}

// NewMockAdminTokenCacheStore creates a new mock admin token cache store
func NewMockAdminTokenCacheStore() *MockAdminTokenCacheStore {
	return &MockAdminTokenCacheStore{
		cache: make(map[string]CacheItem),
	}
}

// Get implements domain.AdminTokenCacheStore
func (m *MockAdminTokenCacheStore) Get(ctx context.Context, key string) (*domain.AdminUserContext, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.cache[key]
	if !exists {
		m.Misses++
		return nil, nil
	}

	// Check if expired
	if time.Now().After(item.ExpiresAt) {
		m.Misses++
		return nil, nil
	}

	m.Hits++
	if adminCtx, ok := item.Value.(*domain.AdminUserContext); ok {
		return adminCtx, nil
	}

	return nil, fmt.Errorf("invalid type in cache")
}

// Set implements domain.AdminTokenCacheStore
func (m *MockAdminTokenCacheStore) Set(ctx context.Context, key string, value *domain.AdminUserContext, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Sets++
	m.cache[key] = CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}

	return nil
}

// GetHitRatio returns the cache hit ratio for benchmarking
func (m *MockAdminTokenCacheStore) GetHitRatio() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := m.Hits + m.Misses
	if total == 0 {
		return 0.0
	}
	return float64(m.Hits) / float64(total)
}

// Reset clears all cache for reuse in tests
func (m *MockAdminTokenCacheStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache = make(map[string]CacheItem)
	m.Hits = 0
	m.Misses = 0
	m.Sets = 0
}

// MockKillSwitchPublisher implements domain.KillSwitchPublisher
type MockKillSwitchPublisher struct {
	publishedMessages map[string][]domain.KillSwitchMessage
	mu                sync.RWMutex

	// Metrics for benchmarking
	PublishCount int64
}

// NewMockKillSwitchPublisher creates a new mock kill switch publisher
func NewMockKillSwitchPublisher() *MockKillSwitchPublisher {
	return &MockKillSwitchPublisher{
		publishedMessages: make(map[string][]domain.KillSwitchMessage),
	}
}

// PublishSessionKill implements domain.KillSwitchPublisher
func (m *MockKillSwitchPublisher) PublishSessionKill(ctx context.Context, channel string, message domain.KillSwitchMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.PublishCount++
	if m.publishedMessages[channel] == nil {
		m.publishedMessages[channel] = make([]domain.KillSwitchMessage, 0)
	}
	m.publishedMessages[channel] = append(m.publishedMessages[channel], message)

	return nil
}

// GetPublishedMessages returns all published messages for testing
func (m *MockKillSwitchPublisher) GetPublishedMessages(channel string) []domain.KillSwitchMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.publishedMessages[channel]
}

// Reset clears all published messages for reuse in tests
func (m *MockKillSwitchPublisher) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.publishedMessages = make(map[string][]domain.KillSwitchMessage)
	m.PublishCount = 0
}

// MockRedisClient implements a minimal redis.Client interface for testing
type MockRedisClient struct {
	data map[string]interface{}
	mu   sync.RWMutex
}

// NewMockRedisClient creates a new mock Redis client
func NewMockRedisClient() *redis.Client {
	// Return a real redis.Client but it won't be used since we're mocking
	// the dependent services that actually use Redis
	return &redis.Client{}
}

// MockKillSwitchSubscriber implements domain.KillSwitchSubscriber for testing
type MockKillSwitchSubscriber struct {
	subscriptions map[string]bool
	messages      map[string][]domain.KillSwitchMessage
	mu            sync.RWMutex

	// Metrics for benchmarking
	SubscriptionCount int64
	MessageCount      int64
}

// NewMockKillSwitchSubscriber creates a new mock kill switch subscriber
func NewMockKillSwitchSubscriber() *MockKillSwitchSubscriber {
	return &MockKillSwitchSubscriber{
		subscriptions: make(map[string]bool),
		messages:      make(map[string][]domain.KillSwitchMessage),
	}
}

// SubscribeToSessionKillPattern implements domain.KillSwitchSubscriber
func (m *MockKillSwitchSubscriber) SubscribeToSessionKillPattern(ctx context.Context, pattern string, handler domain.KillSwitchMessageHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.subscriptions[pattern] = true
	atomic.AddInt64(&m.SubscriptionCount, 1)

	// For testing, we don't actually start a subscription loop
	return nil
}

// Close implements domain.KillSwitchSubscriber
func (m *MockKillSwitchSubscriber) Close() error {
	// For testing, this is a no-op
	return nil
}

// GetSubscribedChannels returns the list of subscribed channels
func (m *MockKillSwitchSubscriber) GetSubscribedChannels() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	channels := make([]string, 0, len(m.subscriptions))
	for channel := range m.subscriptions {
		channels = append(channels, channel)
	}

	return channels
}

// InjectMessage simulates receiving a kill switch message
func (m *MockKillSwitchSubscriber) InjectMessage(channel string, message domain.KillSwitchMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.messages[channel] = append(m.messages[channel], message)
	atomic.AddInt64(&m.MessageCount, 1)
}

// GetReceivedMessages returns all messages received on a channel
func (m *MockKillSwitchSubscriber) GetReceivedMessages(channel string) []domain.KillSwitchMessage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.messages[channel]
}

// Reset clears all subscriptions and messages
func (m *MockKillSwitchSubscriber) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.subscriptions = make(map[string]bool)
	m.messages = make(map[string][]domain.KillSwitchMessage)
	atomic.StoreInt64(&m.SubscriptionCount, 0)
	atomic.StoreInt64(&m.MessageCount, 0)
}
