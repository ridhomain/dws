package benchmarks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/mocks"
	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/utils"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// setupSessionBenchmark creates a test environment for session management benchmarks
func setupSessionBenchmark(b *testing.B) (*mocks.MockSessionLockManager, *mocks.MockRouteRegistry, *mocks.MockKillSwitchPublisher, *utils.ServiceMetrics) {
	b.Helper()

	// Create mock dependencies
	sessionLockManager := mocks.NewMockSessionLockManager()
	routeRegistry := mocks.NewMockRouteRegistry()
	killSwitchPublisher := mocks.NewMockKillSwitchPublisher()

	// Create service metrics tracker
	serviceMetrics := utils.NewServiceMetrics()

	return sessionLockManager, routeRegistry, killSwitchPublisher, serviceMetrics
}

// BenchmarkSessionLocking tests session lock acquisition and release performance
func BenchmarkSessionLocking(b *testing.B) {
	sessionLockManager, _, _, serviceMetrics := setupSessionBenchmark(b)

	ctx := context.Background()
	podID := "test-pod-123"
	lockTTL := 30 * time.Second

	b.Run("SingleLockAcquisition", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("user_%d", i))
			acquired, err := sessionLockManager.AcquireLock(ctx, sessionKey, podID, lockTTL)
			if err != nil {
				b.Errorf("Lock acquisition failed: %v", err)
			}
			if !acquired {
				b.Errorf("Expected to acquire lock for session: %s", sessionKey)
			}
		}

		attempts, successes, _, _, _, _, _ := sessionLockManager.GetMetrics()
		serviceMetrics.UpdateSessionMetrics(attempts, successes)
		b.Logf("Lock acquisition - Attempts: %d, Successes: %d", attempts, successes)
	})

	b.Run("ConcurrentLockAcquisition", func(b *testing.B) {
		sessionLockManager.Reset()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			lockIndex := 0
			for pb.Next() {
				sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("concurrent_user_%d", lockIndex))
				acquired, err := sessionLockManager.AcquireLock(ctx, sessionKey, podID, lockTTL)
				if err != nil {
					b.Errorf("Concurrent lock acquisition failed: %v", err)
				}
				if !acquired {
					b.Errorf("Expected to acquire lock for session: %s", sessionKey)
				}
				lockIndex++
			}
		})

		attempts, successes, _, _, _, _, _ := sessionLockManager.GetMetrics()
		serviceMetrics.UpdateSessionMetrics(attempts, successes)
		b.Logf("Concurrent lock acquisition - Attempts: %d, Successes: %d", attempts, successes)
	})

	b.Run("LockConflictScenario", func(b *testing.B) {
		sessionLockManager.Reset()
		conflictSessionKey := fmt.Sprintf("session:%s:%s:conflict_user", testCompanyID, testAgentID)

		// Pre-acquire the lock
		acquired, err := sessionLockManager.AcquireLock(ctx, conflictSessionKey, "pod-1", lockTTL)
		if err != nil || !acquired {
			b.Fatalf("Failed to pre-acquire lock for conflict test")
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Try to acquire the same lock with different pod ID
			acquired, err := sessionLockManager.AcquireLock(ctx, conflictSessionKey, "pod-2", lockTTL)
			if err != nil {
				b.Errorf("Lock conflict test failed with error: %v", err)
			}
			if acquired {
				b.Errorf("Expected lock acquisition to fail due to conflict")
			}
		}

		attempts, successes, _, _, _, _, _ := sessionLockManager.GetMetrics()
		serviceMetrics.UpdateSessionMetrics(attempts, successes)
		b.Logf("Lock conflict - Attempts: %d, Successes: %d", attempts, successes)
	})

	b.Run("LockRefreshPerformance", func(b *testing.B) {
		sessionLockManager.Reset()
		refreshSessionKey := fmt.Sprintf("session:%s:%s:refresh_user", testCompanyID, testAgentID)

		// Pre-acquire the lock
		acquired, err := sessionLockManager.AcquireLock(ctx, refreshSessionKey, podID, lockTTL)
		if err != nil || !acquired {
			b.Fatalf("Failed to pre-acquire lock for refresh test")
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			refreshed, err := sessionLockManager.RefreshLock(ctx, refreshSessionKey, podID, lockTTL)
			if err != nil {
				b.Errorf("Lock refresh failed: %v", err)
			}
			if !refreshed {
				b.Errorf("Expected to refresh lock for session: %s", refreshSessionKey)
			}
		}

		_, _, _, refreshAttempts, refreshSuccesses, _, _ := sessionLockManager.GetMetrics()
		b.Logf("Lock refresh - Attempts: %d, Successes: %d", refreshAttempts, refreshSuccesses)
	})

	b.Run("LockReleasePerformance", func(b *testing.B) {
		sessionLockManager.Reset()

		// Pre-acquire locks for release testing
		sessionKeys := make([]string, b.N)
		for i := 0; i < b.N; i++ {
			sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("release_user_%d", i))
			acquired, err := sessionLockManager.AcquireLock(ctx, sessionKeys[i], podID, lockTTL)
			if err != nil || !acquired {
				b.Fatalf("Failed to pre-acquire lock %d for release test", i)
			}
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			released, err := sessionLockManager.ReleaseLock(ctx, sessionKeys[i], podID)
			if err != nil {
				b.Errorf("Lock release failed: %v", err)
			}
			if !released {
				b.Errorf("Expected to release lock for session: %s", sessionKeys[i])
			}
		}

		_, _, _, _, _, releaseAttempts, releaseSuccesses := sessionLockManager.GetMetrics()
		b.Logf("Lock release - Attempts: %d, Successes: %d", releaseAttempts, releaseSuccesses)
	})
}

// BenchmarkRouteRegistry tests route registration and lookup performance
func BenchmarkRouteRegistry(b *testing.B) {
	_, routeRegistry, _, serviceMetrics := setupSessionBenchmark(b)

	ctx := context.Background()
	podID := "test-pod-123"
	routeTTL := 30 * time.Second

	b.Run("ChatRouteRegistration", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			agentID := fmt.Sprintf("agent_%d", i)
			err := routeRegistry.RegisterChatRoute(ctx, testCompanyID, agentID, podID, routeTTL)
			if err != nil {
				b.Errorf("Chat route registration failed: %v", err)
			}
		}

		b.Logf("Registered %d chat routes", routeRegistry.RegistrationCount)
		serviceMetrics.UpdateRouteMetrics(routeRegistry.RegistrationCount, routeRegistry.LookupCount)
	})

	b.Run("MessageRouteRegistration", func(b *testing.B) {
		routeRegistry.Reset()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			chatID := fmt.Sprintf("chat_%d", i)
			err := routeRegistry.RegisterMessageRoute(ctx, testCompanyID, testAgentID, chatID, podID, routeTTL)
			if err != nil {
				b.Errorf("Message route registration failed: %v", err)
			}
		}

		b.Logf("Registered %d message routes", routeRegistry.RegistrationCount)
		serviceMetrics.UpdateRouteMetrics(routeRegistry.RegistrationCount, routeRegistry.LookupCount)
	})

	b.Run("ConcurrentRouteRegistration", func(b *testing.B) {
		routeRegistry.Reset()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			routeIndex := 0
			for pb.Next() {
				agentID := fmt.Sprintf("concurrent_agent_%d", routeIndex)
				chatID := fmt.Sprintf("concurrent_chat_%d", routeIndex)

				// Register both chat and message routes
				err1 := routeRegistry.RegisterChatRoute(ctx, testCompanyID, agentID, podID, routeTTL)
				err2 := routeRegistry.RegisterMessageRoute(ctx, testCompanyID, agentID, chatID, podID, routeTTL)

				if err1 != nil {
					b.Errorf("Concurrent chat route registration failed: %v", err1)
				}
				if err2 != nil {
					b.Errorf("Concurrent message route registration failed: %v", err2)
				}
				routeIndex++
			}
		})

		b.Logf("Concurrent registration - Total routes: %d", routeRegistry.RegistrationCount)
		serviceMetrics.UpdateRouteMetrics(routeRegistry.RegistrationCount, routeRegistry.LookupCount)
	})

	b.Run("RouteLookupPerformance", func(b *testing.B) {
		routeRegistry.Reset()

		// Pre-register routes for lookup testing
		const routeCount = 1000
		for i := 0; i < routeCount; i++ {
			agentID := fmt.Sprintf("lookup_agent_%d", i)
			chatID := fmt.Sprintf("lookup_chat_%d", i)

			routeRegistry.RegisterChatRoute(ctx, testCompanyID, agentID, podID, routeTTL)
			routeRegistry.RegisterMessageRoute(ctx, testCompanyID, agentID, chatID, podID, routeTTL)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			agentID := fmt.Sprintf("lookup_agent_%d", i%routeCount)
			chatID := fmt.Sprintf("lookup_chat_%d", i%routeCount)

			// Lookup chat routes
			pods, err := routeRegistry.GetOwningPodsForChatRoute(ctx, testCompanyID, agentID)
			if err != nil {
				b.Errorf("Chat route lookup failed: %v", err)
			}
			if len(pods) == 0 {
				b.Errorf("Expected to find pods for chat route")
			}

			// Lookup message routes
			pod, err := routeRegistry.GetOwningPodForMessageRoute(ctx, testCompanyID, agentID, chatID)
			if err != nil {
				b.Errorf("Message route lookup failed: %v", err)
			}
			if pod == "" {
				b.Errorf("Expected to find pod for message route")
			}
		}

		b.Logf("Route lookup - Total lookups: %d", routeRegistry.LookupCount)
		serviceMetrics.UpdateRouteMetrics(routeRegistry.RegistrationCount, routeRegistry.LookupCount)
	})

	b.Run("RouteUnregistrationPerformance", func(b *testing.B) {
		routeRegistry.Reset()

		// Pre-register routes for unregistration testing
		agentIDs := make([]string, b.N)
		chatIDs := make([]string, b.N)

		for i := 0; i < b.N; i++ {
			agentIDs[i] = fmt.Sprintf("unreg_agent_%d", i)
			chatIDs[i] = fmt.Sprintf("unreg_chat_%d", i)

			routeRegistry.RegisterChatRoute(ctx, testCompanyID, agentIDs[i], podID, routeTTL)
			routeRegistry.RegisterMessageRoute(ctx, testCompanyID, agentIDs[i], chatIDs[i], podID, routeTTL)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err1 := routeRegistry.UnregisterChatRoute(ctx, testCompanyID, agentIDs[i], podID)
			err2 := routeRegistry.UnregisterMessageRoute(ctx, testCompanyID, agentIDs[i], chatIDs[i], podID)

			if err1 != nil {
				b.Errorf("Chat route unregistration failed: %v", err1)
			}
			if err2 != nil {
				b.Errorf("Message route unregistration failed: %v", err2)
			}
		}

		b.Logf("Route unregistration - Total unregistrations: %d", routeRegistry.UnregistrationCount)
	})
}

// BenchmarkKillSwitchPublisher tests kill switch message publishing performance
func BenchmarkKillSwitchPublisher(b *testing.B) {
	_, _, killSwitchPublisher, serviceMetrics := setupSessionBenchmark(b)

	ctx := context.Background()

	b.Run("SingleKillSwitchPublish", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			channel := fmt.Sprintf("session_kill:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("user_%d", i))
			message := domain.KillSwitchMessage{
				NewPodID: "new-pod-123",
			}

			err := killSwitchPublisher.PublishSessionKill(ctx, channel, message)
			if err != nil {
				b.Errorf("Kill switch publish failed: %v", err)
			}
		}

		b.Logf("Published %d kill switch messages", killSwitchPublisher.PublishCount)
		serviceMetrics.UpdateKillSwitchMetrics(killSwitchPublisher.PublishCount)
	})

	b.Run("ConcurrentKillSwitchPublish", func(b *testing.B) {
		killSwitchPublisher.Reset()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			publishIndex := 0
			for pb.Next() {
				channel := fmt.Sprintf("session_kill:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("concurrent_user_%d", publishIndex))
				message := domain.KillSwitchMessage{
					NewPodID: "concurrent-pod-123",
				}

				err := killSwitchPublisher.PublishSessionKill(ctx, channel, message)
				if err != nil {
					b.Errorf("Concurrent kill switch publish failed: %v", err)
				}
				publishIndex++
			}
		})

		b.Logf("Concurrent published %d kill switch messages", killSwitchPublisher.PublishCount)
		serviceMetrics.UpdateKillSwitchMetrics(killSwitchPublisher.PublishCount)
	})

	b.Run("BulkKillSwitchPublish", func(b *testing.B) {
		killSwitchPublisher.Reset()
		scales := []int{10, 100, 1000}

		for _, scale := range scales {
			b.Run(fmt.Sprintf("Scale_%d", scale), func(b *testing.B) {
				channels := make([]string, scale)
				messages := make([]domain.KillSwitchMessage, scale)

				// Pre-create channels and messages
				for i := 0; i < scale; i++ {
					channels[i] = fmt.Sprintf("session_kill:%s:%s:%s", testCompanyID, testAgentID, fmt.Sprintf("bulk_user_%d_%d", scale, i))
					messages[i] = domain.KillSwitchMessage{
						NewPodID: fmt.Sprintf("bulk-pod-%d", i),
					}
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					batchIndex := i % scale
					err := killSwitchPublisher.PublishSessionKill(ctx, channels[batchIndex], messages[batchIndex])
					if err != nil {
						b.Errorf("Bulk kill switch publish failed at scale %d: %v", scale, err)
					}
				}

				b.Logf("Scale %d - Published %d messages", scale, killSwitchPublisher.PublishCount)
			})
		}
	})
}

// BenchmarkSessionIntegration tests integrated session management scenarios
func BenchmarkSessionIntegration(b *testing.B) {
	sessionLockManager, routeRegistry, killSwitchPublisher, serviceMetrics := setupSessionBenchmark(b)

	ctx := context.Background()
	podID := "integration-pod-123"
	lockTTL := 30 * time.Second
	routeTTL := 30 * time.Second

	b.Run("FullSessionLifecycle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userID := fmt.Sprintf("integration_user_%d", i)
			sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
			chatID := fmt.Sprintf("chat_%d", i)

			// 1. Acquire session lock
			acquired, err := sessionLockManager.AcquireLock(ctx, sessionKey, podID, lockTTL)
			if err != nil || !acquired {
				b.Errorf("Failed to acquire session lock: %v", err)
				continue
			}

			// 2. Register routes
			err1 := routeRegistry.RegisterChatRoute(ctx, testCompanyID, testAgentID, podID, routeTTL)
			err2 := routeRegistry.RegisterMessageRoute(ctx, testCompanyID, testAgentID, chatID, podID, routeTTL)
			if err1 != nil || err2 != nil {
				b.Errorf("Failed to register routes: %v, %v", err1, err2)
				continue
			}

			// 3. Simulate session activity (refresh lock)
			refreshed, err := sessionLockManager.RefreshLock(ctx, sessionKey, podID, lockTTL)
			if err != nil || !refreshed {
				b.Errorf("Failed to refresh session lock: %v", err)
				continue
			}

			// 4. Cleanup: unregister routes and release lock
			routeRegistry.UnregisterChatRoute(ctx, testCompanyID, testAgentID, podID)
			routeRegistry.UnregisterMessageRoute(ctx, testCompanyID, testAgentID, chatID, podID)
			sessionLockManager.ReleaseLock(ctx, sessionKey, podID)
		}

		lockAttempts, lockSuccesses, _, _, _, _, _ := sessionLockManager.GetMetrics()
		serviceMetrics.UpdateSessionMetrics(lockAttempts, lockSuccesses)
		serviceMetrics.UpdateRouteMetrics(routeRegistry.RegistrationCount, routeRegistry.LookupCount)

		b.Logf("Integration test - Lock attempts: %d, successes: %d, routes: %d",
			lockAttempts, lockSuccesses, routeRegistry.RegistrationCount)
	})

	b.Run("SessionConflictWithKillSwitch", func(b *testing.B) {
		sessionLockManager.Reset()
		killSwitchPublisher.Reset()

		conflictSessionKey := fmt.Sprintf("session:%s:%s:conflict_user", testCompanyID, testAgentID)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Pod 1 acquires the lock
			acquired, err := sessionLockManager.AcquireLock(ctx, conflictSessionKey, "pod-1", lockTTL)
			if err != nil || !acquired {
				b.Errorf("Pod 1 failed to acquire lock: %v", err)
				continue
			}

			// Pod 2 tries to acquire the same lock (should fail)
			acquired2, err := sessionLockManager.AcquireLock(ctx, conflictSessionKey, "pod-2", lockTTL)
			if err != nil {
				b.Errorf("Pod 2 lock attempt failed with error: %v", err)
				continue
			}
			if acquired2 {
				b.Errorf("Pod 2 should not have acquired the lock")
				continue
			}

			// Pod 2 force acquires the lock and publishes kill switch
			forceAcquired, err := sessionLockManager.ForceAcquireLock(ctx, conflictSessionKey, "pod-2", lockTTL)
			if err != nil || !forceAcquired {
				b.Errorf("Pod 2 failed to force acquire lock: %v", err)
				continue
			}

			// Publish kill switch message
			channel := fmt.Sprintf("session_kill:%s", conflictSessionKey)
			message := domain.KillSwitchMessage{NewPodID: "pod-2"}
			err = killSwitchPublisher.PublishSessionKill(ctx, channel, message)
			if err != nil {
				b.Errorf("Failed to publish kill switch: %v", err)
				continue
			}

			// Cleanup
			sessionLockManager.ReleaseLock(ctx, conflictSessionKey, "pod-2")
		}

		b.Logf("Session conflict test - Kill switch messages: %d", killSwitchPublisher.PublishCount)
		serviceMetrics.UpdateKillSwitchMetrics(killSwitchPublisher.PublishCount)
	})
}
