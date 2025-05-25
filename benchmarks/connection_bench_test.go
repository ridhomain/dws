package benchmarks

import (
	"fmt"
	"testing"

	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/mocks"
	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/utils"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
)

// setupConnectionBenchmark creates a test environment for connection management benchmarks
func setupConnectionBenchmark(b *testing.B) (*application.ConnectionManager, *utils.ServiceMetrics) {
	b.Helper()

	// Create mock config provider
	mockConfig := mocks.NewMockConfigProvider()

	// Create mock dependencies
	logger := mocks.NewMockLogger()
	sessionLockManager := mocks.NewMockSessionLockManager()
	routeRegistry := mocks.NewMockRouteRegistry()
	killSwitchPublisher := mocks.NewMockKillSwitchPublisher()
	killSwitchSubscriber := mocks.NewMockKillSwitchSubscriber()
	redisClient := mocks.NewMockRedisClient()

	// Create connection manager
	connectionManager := application.NewConnectionManager(
		logger,
		mockConfig,
		sessionLockManager,
		killSwitchPublisher,
		killSwitchSubscriber,
		routeRegistry,
		redisClient,
	)

	// Create service metrics tracker
	serviceMetrics := utils.NewServiceMetrics()

	return connectionManager, serviceMetrics
}

// BenchmarkConnectionRegistration tests connection registration performance
func BenchmarkConnectionRegistration(b *testing.B) {
	connectionManager, serviceMetrics := setupConnectionBenchmark(b)

	b.Run("SingleConnectionRegistration", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			connID := fmt.Sprintf("conn_%d", i)
			mockConn := utils.NewMockWebSocketConnection(
				connID,
				testCompanyID,
				testAgentID,
				fmt.Sprintf("user_%d", i),
				fmt.Sprintf("token_%d", i),
				100,
				utils.BackpressureDrop,
			)

			sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("user_%d", i))
			connectionManager.RegisterConnection(sessionKey, mockConn, testCompanyID, testAgentID)

			// Update metrics
			serviceMetrics.UpdateConnectionMetrics(1, 1)
		}
	})

	b.Run("ConcurrentConnectionRegistration", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			connIndex := 0
			for pb.Next() {
				connID := fmt.Sprintf("concurrent_conn_%d", connIndex)
				mockConn := utils.NewMockWebSocketConnection(
					connID,
					testCompanyID,
					testAgentID,
					fmt.Sprintf("concurrent_user_%d", connIndex),
					fmt.Sprintf("concurrent_token_%d", connIndex),
					100,
					utils.BackpressureDrop,
				)

				sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("concurrent_user_%d", connIndex))
				connectionManager.RegisterConnection(sessionKey, mockConn, testCompanyID, testAgentID)

				serviceMetrics.UpdateConnectionMetrics(1, 1)
				connIndex++
			}
		})
	})

	b.Run("BulkConnectionRegistration", func(b *testing.B) {
		scales := []int{10, 100, 1000}

		for _, scale := range scales {
			b.Run(fmt.Sprintf("Scale_%d", scale), func(b *testing.B) {
				connections := make([]*utils.MockWebSocketConnection, scale)
				sessionKeys := make([]string, scale)

				// Pre-create connections
				for i := 0; i < scale; i++ {
					connections[i] = utils.NewMockWebSocketConnection(
						fmt.Sprintf("bulk_conn_%d_%d", scale, i),
						testCompanyID,
						testAgentID,
						fmt.Sprintf("bulk_user_%d_%d", scale, i),
						fmt.Sprintf("bulk_token_%d_%d", scale, i),
						100,
						utils.BackpressureDrop,
					)

					sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("bulk_user_%d_%d", scale, i))
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					batchIndex := i % scale
					connectionManager.RegisterConnection(sessionKeys[batchIndex], connections[batchIndex], testCompanyID, testAgentID)
				}

				serviceMetrics.UpdateConnectionMetrics(int64(scale), int64(scale))
			})
		}
	})
}

// BenchmarkConnectionDeregistration tests connection cleanup performance
func BenchmarkConnectionDeregistration(b *testing.B) {
	connectionManager, serviceMetrics := setupConnectionBenchmark(b)

	b.Run("SingleConnectionDeregistration", func(b *testing.B) {
		// Pre-register connections for deregistration
		connections := make([]*utils.MockWebSocketConnection, b.N)
		sessionKeys := make([]string, b.N)

		for i := 0; i < b.N; i++ {
			connections[i] = utils.NewMockWebSocketConnection(
				fmt.Sprintf("dereg_conn_%d", i),
				testCompanyID,
				testAgentID,
				fmt.Sprintf("dereg_user_%d", i),
				fmt.Sprintf("dereg_token_%d", i),
				100,
				utils.BackpressureDrop,
			)

			sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("dereg_user_%d", i))
			connectionManager.RegisterConnection(sessionKeys[i], connections[i], testCompanyID, testAgentID)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			connectionManager.DeregisterConnection(sessionKeys[i])
			serviceMetrics.UpdateConnectionMetrics(-1, 0)
		}
	})

	b.Run("ConcurrentConnectionDeregistration", func(b *testing.B) {
		// Pre-register many connections
		const preRegCount = 10000
		connections := make([]*utils.MockWebSocketConnection, preRegCount)
		sessionKeys := make([]string, preRegCount)

		for i := 0; i < preRegCount; i++ {
			connections[i] = utils.NewMockWebSocketConnection(
				fmt.Sprintf("concurrent_dereg_conn_%d", i),
				testCompanyID,
				testAgentID,
				fmt.Sprintf("concurrent_dereg_user_%d", i),
				fmt.Sprintf("concurrent_dereg_token_%d", i),
				100,
				utils.BackpressureDrop,
			)

			sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("concurrent_dereg_user_%d", i))
			connectionManager.RegisterConnection(sessionKeys[i], connections[i], testCompanyID, testAgentID)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			connIndex := 0
			for pb.Next() {
				if connIndex < preRegCount {
					connectionManager.DeregisterConnection(sessionKeys[connIndex])
					serviceMetrics.UpdateConnectionMetrics(-1, 0)
					connIndex++
				}
			}
		})
	})
}

// BenchmarkConnectionLifecycle tests full connection lifecycle performance
func BenchmarkConnectionLifecycle(b *testing.B) {
	connectionManager, serviceMetrics := setupConnectionBenchmark(b)

	b.Run("FullLifecycle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// 1. Create connection
			mockConn := utils.NewMockWebSocketConnection(
				fmt.Sprintf("lifecycle_conn_%d", i),
				testCompanyID,
				testAgentID,
				fmt.Sprintf("lifecycle_user_%d", i),
				fmt.Sprintf("lifecycle_token_%d", i),
				100,
				utils.BackpressureDrop,
			)

			// 2. Register connection
			sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("lifecycle_user_%d", i))
			connectionManager.RegisterConnection(sessionKey, mockConn, testCompanyID, testAgentID)

			// 3. Deregister connection
			connectionManager.DeregisterConnection(sessionKey)

			serviceMetrics.UpdateConnectionMetrics(0, 1)
		}
	})

	b.Run("ConcurrentLifecycle", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			lifecycleIndex := 0
			for pb.Next() {
				// Full lifecycle test in concurrent scenario
				mockConn := utils.NewMockWebSocketConnection(
					fmt.Sprintf("concurrent_lifecycle_conn_%d", lifecycleIndex),
					testCompanyID,
					testAgentID,
					fmt.Sprintf("concurrent_lifecycle_user_%d", lifecycleIndex),
					fmt.Sprintf("concurrent_lifecycle_token_%d", lifecycleIndex),
					100,
					utils.BackpressureDrop,
				)

				// Register
				sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("concurrent_lifecycle_user_%d", lifecycleIndex))
				connectionManager.RegisterConnection(sessionKey, mockConn, testCompanyID, testAgentID)

				// Deregister
				connectionManager.DeregisterConnection(sessionKey)

				serviceMetrics.UpdateConnectionMetrics(0, 1)
				lifecycleIndex++
			}
		})
	})
}

// BenchmarkConnectionMemoryUsage tests memory overhead per connection
func BenchmarkConnectionMemoryUsage(b *testing.B) {
	connectionManager, serviceMetrics := setupConnectionBenchmark(b)
	scales := []int{100, 1000, 5000}

	for _, scale := range scales {
		b.Run(fmt.Sprintf("MemoryUsage_Scale_%d", scale), func(b *testing.B) {
			connections := make([]*utils.MockWebSocketConnection, scale)
			sessionKeys := make([]string, scale)

			// Pre-create all objects
			for i := 0; i < scale; i++ {
				connections[i] = utils.NewMockWebSocketConnection(
					fmt.Sprintf("memory_conn_%d_%d", scale, i),
					testCompanyID,
					testAgentID,
					fmt.Sprintf("memory_user_%d_%d", scale, i),
					fmt.Sprintf("memory_token_%d_%d", scale, i),
					50, // Smaller buffer for memory testing
					utils.BackpressureDrop,
				)

				sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("memory_user_%d_%d", scale, i))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				batchIndex := i % scale
				connectionManager.RegisterConnection(sessionKeys[batchIndex], connections[batchIndex], testCompanyID, testAgentID)
			}

			serviceMetrics.UpdateConnectionMetrics(int64(scale), int64(scale))
			b.Logf("Scale %d completed with %d active connections", scale, scale)
		})
	}
}
