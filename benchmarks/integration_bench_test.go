package benchmarks

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/mocks"
	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/utils"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
)

// setupIntegrationBenchmark creates a complete test environment for integration benchmarks
func setupIntegrationBenchmark(b *testing.B) (*application.AuthService, *application.ConnectionManager, *mocks.MockNatsConsumer, *utils.WebSocketClientPool, *utils.ServiceMetrics) {
	b.Helper()

	// Create mock config provider
	mockConfig := mocks.NewMockConfigProvider()

	// Create mock dependencies
	logger := mocks.NewMockLogger()
	userCache := mocks.NewMockTokenCacheStore()
	adminCache := mocks.NewMockAdminTokenCacheStore()
	sessionLockManager := mocks.NewMockSessionLockManager()
	routeRegistry := mocks.NewMockRouteRegistry()
	killSwitchPublisher := mocks.NewMockKillSwitchPublisher()
	killSwitchSubscriber := mocks.NewMockKillSwitchSubscriber()
	redisClient := mocks.NewMockRedisClient()
	natsConsumer := mocks.NewMockNatsConsumer()

	// Create services
	authService := application.NewAuthService(logger, mockConfig, userCache, adminCache)
	connectionManager := application.NewConnectionManager(
		logger,
		mockConfig,
		sessionLockManager,
		killSwitchPublisher,
		killSwitchSubscriber,
		routeRegistry,
		redisClient,
	)

	// Create WebSocket client pool
	clientPool := utils.NewWebSocketClientPool()

	// Create service metrics tracker
	serviceMetrics := utils.NewServiceMetrics()

	return authService, connectionManager, natsConsumer, clientPool, serviceMetrics
}

// BenchmarkFullUserFlow tests complete user authentication and connection flow
func BenchmarkFullUserFlow(b *testing.B) {
	authService, connectionManager, _, clientPool, serviceMetrics := setupIntegrationBenchmark(b)

	// Create token generator with proper keys
	mockConfig := mocks.NewMockConfigProvider()
	cfg := mockConfig.Get()
	tokenGen, err := utils.NewTokenGenerator(cfg.Auth.TokenAESKey, cfg.Auth.AdminTokenAESKey)
	if err != nil {
		b.Fatalf("Failed to create token generator: %v", err)
	}

	ctx := context.Background()

	b.Run("SingleUserFlow", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userID := fmt.Sprintf("user_%d", i)
			token, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
			if err != nil {
				b.Errorf("Failed to generate token: %v", err)
				continue
			}

			// 1. Authenticate user
			userCtx, err := authService.ProcessToken(ctx, token)
			if err != nil {
				b.Errorf("Authentication failed: %v", err)
				continue
			}

			// 2. Create WebSocket connection
			mockConn := utils.NewMockWebSocketConnection(
				fmt.Sprintf("conn_%d", i),
				testCompanyID,
				testAgentID,
				userID,
				token,
				100,
				utils.BackpressureDrop,
			)

			// Connect the mock connection
			if err := mockConn.Connect(); err != nil {
				b.Errorf("Failed to connect mock WebSocket: %v", err)
				continue
			}

			// 3. Register connection
			sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
			connectionManager.RegisterConnection(sessionKey, mockConn, testCompanyID, testAgentID)

			// 4. Simulate some activity
			err = mockConn.WriteJSON(map[string]interface{}{
				"type": "ready",
				"data": map[string]interface{}{
					"user_id": userCtx.UserID,
				},
			})
			if err != nil {
				b.Errorf("Failed to send ready message: %v", err)
			}

			// 5. Cleanup
			connectionManager.DeregisterConnection(sessionKey)
			clientPool.RemoveConnection(fmt.Sprintf("conn_%d", i))
		}

		serviceMetrics.UpdateConnectionMetrics(0, int64(b.N))
		serviceMetrics.UpdateAuthMetrics(int64(b.N), 0)
	})

	b.Run("ConcurrentUserFlow", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			userIndex := 0
			for pb.Next() {
				userID := fmt.Sprintf("concurrent_user_%d", userIndex)
				token, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
				if err != nil {
					b.Errorf("Failed to generate token: %v", err)
					userIndex++
					continue
				}

				// Full flow in concurrent scenario
				userCtx, err := authService.ProcessToken(ctx, token)
				if err != nil {
					b.Errorf("Concurrent authentication failed: %v", err)
					userIndex++
					continue
				}

				mockConn := utils.NewMockWebSocketConnection(
					fmt.Sprintf("concurrent_conn_%d", userIndex),
					testCompanyID,
					testAgentID,
					userID,
					token,
					100,
					utils.BackpressureDrop,
				)

				// Connect the mock connection
				if err := mockConn.Connect(); err != nil {
					b.Errorf("Failed to connect concurrent mock WebSocket: %v", err)
					userIndex++
					continue
				}

				sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
				connectionManager.RegisterConnection(sessionKey, mockConn, testCompanyID, testAgentID)

				// Simulate activity
				mockConn.WriteJSON(map[string]interface{}{
					"type": "ping",
					"data": map[string]interface{}{
						"user_id":   userCtx.UserID,
						"timestamp": time.Now().Unix(),
					},
				})

				// Cleanup
				connectionManager.DeregisterConnection(sessionKey)
				userIndex++
			}
		})

		serviceMetrics.UpdateConnectionMetrics(0, int64(b.N))
		serviceMetrics.UpdateAuthMetrics(int64(b.N), 0)
	})
}

// BenchmarkMessageFlow tests end-to-end message processing
func BenchmarkMessageFlow(b *testing.B) {
	authService, connectionManager, natsConsumer, clientPool, serviceMetrics := setupIntegrationBenchmark(b)

	// Create token generator with proper keys
	mockConfig := mocks.NewMockConfigProvider()
	cfg := mockConfig.Get()
	tokenGen, err := utils.NewTokenGenerator(cfg.Auth.TokenAESKey, cfg.Auth.AdminTokenAESKey)
	if err != nil {
		b.Fatalf("Failed to create token generator: %v", err)
	}
	eventGen := utils.NewEventPayloadGenerator()

	ctx := context.Background()

	b.Run("SingleMessageFlow", func(b *testing.B) {
		// Pre-setup authenticated connections
		const connectionCount = 10
		connections := make([]*utils.MockWebSocketConnection, connectionCount)
		sessionKeys := make([]string, connectionCount)

		for i := 0; i < connectionCount; i++ {
			userID := fmt.Sprintf("msg_user_%d", i)
			token, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
			if err != nil {
				b.Fatalf("Failed to generate token for user %d: %v", i, err)
			}

			_, err = authService.ProcessToken(ctx, token)
			if err != nil {
				b.Fatalf("Failed to authenticate user %d: %v", i, err)
			}

			connections[i] = utils.NewMockWebSocketConnection(
				fmt.Sprintf("msg_conn_%d", i),
				testCompanyID,
				testAgentID,
				userID,
				token,
				100,
				utils.BackpressureDrop,
			)

			// Connect the mock connection
			if err := connections[i].Connect(); err != nil {
				b.Fatalf("Failed to connect message flow connection %d: %v", i, err)
			}

			sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
			connectionManager.RegisterConnection(sessionKeys[i], connections[i], testCompanyID, testAgentID)
			clientPool.AddConnection(connections[i])
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// 1. Generate NATS event
			chatID := fmt.Sprintf("chat_%d", i%5) // Distribute across 5 chats
			messageID := fmt.Sprintf("msg_%d", i)
			event := eventGen.GenerateMessageEvent(testCompanyID, testAgentID, chatID, messageID)

			// 2. Simulate NATS message processing
			eventData, err := eventGen.SerializeEvent(event)
			if err != nil {
				b.Errorf("Failed to serialize event: %v", err)
				continue
			}

			// Simulate NATS message processing
			natsConsumer.InjectMessage("events."+testCompanyID+"."+testAgentID, eventData)

			// 3. Broadcast to WebSocket connections
			connIndex := i % connectionCount
			err = connections[connIndex].WriteJSON(map[string]interface{}{
				"type": "event",
				"data": event,
			})
			if err != nil {
				b.Errorf("Failed to send message to WebSocket: %v", err)
				continue
			}
		}

		// Cleanup
		for i := 0; i < connectionCount; i++ {
			connectionManager.DeregisterConnection(sessionKeys[i])
		}

		serviceMetrics.UpdateMessageMetrics(int64(b.N), int64(b.N), 0)
	})

	b.Run("BulkMessageFlow", func(b *testing.B) {
		scales := []int{10, 100, 1000}

		for _, scale := range scales {
			b.Run(fmt.Sprintf("Scale_%d", scale), func(b *testing.B) {
				// Pre-generate events
				events := eventGen.GenerateBulkEvents(scale, testCompanyID, testAgentID)

				// Pre-setup connections
				connections := make([]*utils.MockWebSocketConnection, scale)
				sessionKeys := make([]string, scale)

				for i := 0; i < scale; i++ {
					userID := fmt.Sprintf("bulk_user_%d_%d", scale, i)
					token, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
					if err != nil {
						b.Fatalf("Failed to generate token for bulk user %d: %v", i, err)
					}

					_, err = authService.ProcessToken(ctx, token)
					if err != nil {
						b.Fatalf("Failed to authenticate bulk user %d: %v", i, err)
					}

					connections[i] = utils.NewMockWebSocketConnection(
						fmt.Sprintf("bulk_conn_%d_%d", scale, i),
						testCompanyID,
						testAgentID,
						userID,
						token,
						50, // Smaller buffer for bulk testing
						utils.BackpressureDrop,
					)

					// Connect the mock connection
					if err := connections[i].Connect(); err != nil {
						b.Fatalf("Failed to connect bulk connection %d: %v", i, err)
					}

					sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
					connectionManager.RegisterConnection(sessionKeys[i], connections[i], testCompanyID, testAgentID)
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					eventIndex := i % scale
					connIndex := i % scale

					// Process event through NATS
					eventData, _ := eventGen.SerializeEvent(events[eventIndex])
					natsConsumer.InjectMessage("events."+testCompanyID+"."+testAgentID, eventData)

					// Send to WebSocket
					connections[connIndex].WriteJSON(map[string]interface{}{
						"type": "bulk_event",
						"data": events[eventIndex],
					})
				}

				// Cleanup
				for i := 0; i < scale; i++ {
					connectionManager.DeregisterConnection(sessionKeys[i])
				}

				b.Logf("Scale %d - Processed %d messages", scale, b.N)
			})
		}
	})
}

// BenchmarkSessionManagementFlow tests session lifecycle with conflicts
func BenchmarkSessionManagementFlow(b *testing.B) {
	authService, connectionManager, _, _, serviceMetrics := setupIntegrationBenchmark(b)

	// Create token generator with proper keys
	mockConfig := mocks.NewMockConfigProvider()
	cfg := mockConfig.Get()
	tokenGen, err := utils.NewTokenGenerator(cfg.Auth.TokenAESKey, cfg.Auth.AdminTokenAESKey)
	if err != nil {
		b.Fatalf("Failed to create token generator: %v", err)
	}

	ctx := context.Background()

	b.Run("SessionConflictResolution", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userID := fmt.Sprintf("conflict_user_%d", i)
			token1, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
			if err != nil {
				b.Errorf("Failed to generate first token: %v", err)
				continue
			}
			token2, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
			if err != nil {
				b.Errorf("Failed to generate second token: %v", err)
				continue
			}

			// 1. First connection
			userCtx1, err := authService.ProcessToken(ctx, token1)
			if err != nil {
				b.Errorf("First authentication failed: %v", err)
				continue
			}

			conn1 := utils.NewMockWebSocketConnection(
				fmt.Sprintf("conflict_conn1_%d", i),
				testCompanyID,
				testAgentID,
				userID,
				token1,
				100,
				utils.BackpressureDrop,
			)

			// Connect the first mock connection
			if err := conn1.Connect(); err != nil {
				b.Errorf("Failed to connect first conflict connection: %v", err)
				continue
			}

			sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
			connectionManager.RegisterConnection(sessionKey, conn1, testCompanyID, testAgentID)

			// 2. Second connection (conflict)
			userCtx2, err := authService.ProcessToken(ctx, token2)
			if err != nil {
				b.Errorf("Second authentication failed: %v", err)
				continue
			}

			conn2 := utils.NewMockWebSocketConnection(
				fmt.Sprintf("conflict_conn2_%d", i),
				testCompanyID,
				testAgentID,
				userID,
				token2,
				100,
				utils.BackpressureDrop,
			)

			// Connect the second mock connection
			if err := conn2.Connect(); err != nil {
				b.Errorf("Failed to connect second conflict connection: %v", err)
				continue
			}

			// This should trigger session conflict resolution
			connectionManager.RegisterConnection(sessionKey, conn2, testCompanyID, testAgentID)

			// 3. Verify both contexts are valid
			if userCtx1.UserID != userCtx2.UserID {
				b.Errorf("User contexts don't match: %s vs %s", userCtx1.UserID, userCtx2.UserID)
			}

			// 4. Cleanup
			connectionManager.DeregisterConnection(sessionKey)
		}

		serviceMetrics.UpdateConnectionMetrics(0, int64(b.N*2))
		serviceMetrics.UpdateAuthMetrics(int64(b.N*2), 0)
	})

	b.Run("MultiPodSessionHandoff", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			userID := fmt.Sprintf("handoff_user_%d", i)
			token, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
			if err != nil {
				b.Errorf("Failed to generate token: %v", err)
				continue
			}

			// 1. Authenticate and connect on pod-1
			userCtx, err := authService.ProcessToken(ctx, token)
			if err != nil {
				b.Errorf("Authentication failed: %v", err)
				continue
			}

			conn := utils.NewMockWebSocketConnection(
				fmt.Sprintf("handoff_conn_%d", i),
				testCompanyID,
				testAgentID,
				userID,
				token,
				100,
				utils.BackpressureDrop,
			)

			// Connect the handoff connection
			if err := conn.Connect(); err != nil {
				b.Errorf("Failed to connect handoff connection: %v", err)
				continue
			}

			sessionKey := fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
			connectionManager.RegisterConnection(sessionKey, conn, testCompanyID, testAgentID)

			// 2. Simulate pod handoff (deregister from pod-1, register on pod-2)
			connectionManager.DeregisterConnection(sessionKey)

			// 3. Re-authenticate and connect on pod-2
			userCtx2, err := authService.ProcessToken(ctx, token)
			if err != nil {
				b.Errorf("Re-authentication failed: %v", err)
				continue
			}

			conn2 := utils.NewMockWebSocketConnection(
				fmt.Sprintf("handoff_conn2_%d", i),
				testCompanyID,
				testAgentID,
				userID,
				token,
				100,
				utils.BackpressureDrop,
			)

			// Connect the second handoff connection
			if err := conn2.Connect(); err != nil {
				b.Errorf("Failed to connect second handoff connection: %v", err)
				continue
			}

			connectionManager.RegisterConnection(sessionKey, conn2, testCompanyID, testAgentID)

			// 4. Verify context consistency
			if userCtx.UserID != userCtx2.UserID {
				b.Errorf("User context changed during handoff: %s vs %s", userCtx.UserID, userCtx2.UserID)
			}

			// 5. Cleanup
			connectionManager.DeregisterConnection(sessionKey)
		}

		serviceMetrics.UpdateConnectionMetrics(0, int64(b.N*2))
		serviceMetrics.UpdateAuthMetrics(int64(b.N*2), 0)
	})
}

// BenchmarkHighLoadScenario tests system behavior under high load
func BenchmarkHighLoadScenario(b *testing.B) {
	authService, connectionManager, natsConsumer, clientPool, serviceMetrics := setupIntegrationBenchmark(b)

	// Create token generator with proper keys
	mockConfig := mocks.NewMockConfigProvider()
	cfg := mockConfig.Get()
	tokenGen, err := utils.NewTokenGenerator(cfg.Auth.TokenAESKey, cfg.Auth.AdminTokenAESKey)
	if err != nil {
		b.Fatalf("Failed to create token generator: %v", err)
	}
	eventGen := utils.NewEventPayloadGenerator()

	ctx := context.Background()

	b.Run("HighConcurrencyLoad", func(b *testing.B) {
		const concurrentUsers = 1000
		const messagesPerUser = 10

		// Pre-setup users and connections
		var wg sync.WaitGroup
		connections := make([]*utils.MockWebSocketConnection, concurrentUsers)
		sessionKeys := make([]string, concurrentUsers)

		// Setup phase
		for i := 0; i < concurrentUsers; i++ {
			userID := fmt.Sprintf("load_user_%d", i)
			token, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
			if err != nil {
				b.Fatalf("Failed to generate token for user %d: %v", i, err)
			}

			_, err = authService.ProcessToken(ctx, token)
			if err != nil {
				b.Fatalf("Failed to authenticate user %d: %v", i, err)
			}

			connections[i] = utils.NewMockWebSocketConnection(
				fmt.Sprintf("load_conn_%d", i),
				testCompanyID,
				testAgentID,
				userID,
				token,
				200, // Larger buffer for high load
				utils.BackpressureBlock,
			)

			// Connect the high load connection
			if err := connections[i].Connect(); err != nil {
				b.Fatalf("Failed to connect high load connection %d: %v", i, err)
			}

			sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
			connectionManager.RegisterConnection(sessionKeys[i], connections[i], testCompanyID, testAgentID)
			clientPool.AddConnection(connections[i])
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			wg.Add(concurrentUsers)

			// Simulate concurrent message processing
			for userIndex := 0; userIndex < concurrentUsers; userIndex++ {
				go func(idx int) {
					defer wg.Done()

					for msgIndex := 0; msgIndex < messagesPerUser; msgIndex++ {
						// Generate and process event
						chatID := fmt.Sprintf("load_chat_%d", idx%10)
						messageID := fmt.Sprintf("load_msg_%d_%d_%d", i, idx, msgIndex)
						event := eventGen.GenerateMessageEvent(testCompanyID, testAgentID, chatID, messageID)

						eventData, _ := eventGen.SerializeEvent(event)
						natsConsumer.InjectMessage("events."+testCompanyID+"."+testAgentID, eventData)

						// Send to WebSocket
						connections[idx].WriteJSON(map[string]interface{}{
							"type": "load_event",
							"data": event,
						})
					}
				}(userIndex)
			}

			wg.Wait()
		}

		// Cleanup
		for i := 0; i < concurrentUsers; i++ {
			connectionManager.DeregisterConnection(sessionKeys[i])
		}

		totalMessages := int64(b.N * concurrentUsers * messagesPerUser)
		serviceMetrics.UpdateMessageMetrics(totalMessages, totalMessages, 0)
		serviceMetrics.UpdateConnectionMetrics(0, int64(concurrentUsers))

		b.Logf("High load test - Users: %d, Messages per iteration: %d, Total messages: %d",
			concurrentUsers, concurrentUsers*messagesPerUser, totalMessages)
	})

	b.Run("MemoryPressureTest", func(b *testing.B) {
		const connectionCount = 5000
		connections := make([]*utils.MockWebSocketConnection, connectionCount)
		sessionKeys := make([]string, connectionCount)

		// Create many connections to test memory usage
		for i := 0; i < connectionCount; i++ {
			userID := fmt.Sprintf("memory_user_%d", i)
			token, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, userID, time.Hour)
			if err != nil {
				b.Fatalf("Failed to generate token for memory user %d: %v", i, err)
			}

			_, err = authService.ProcessToken(ctx, token)
			if err != nil {
				b.Fatalf("Failed to authenticate memory user %d: %v", i, err)
			}

			connections[i] = utils.NewMockWebSocketConnection(
				fmt.Sprintf("memory_conn_%d", i),
				testCompanyID,
				testAgentID,
				userID,
				token,
				10, // Small buffer to test memory efficiency
				utils.BackpressureDrop,
			)

			// Connect the memory pressure connection
			if err := connections[i].Connect(); err != nil {
				b.Fatalf("Failed to connect memory pressure connection %d: %v", i, err)
			}

			sessionKeys[i] = fmt.Sprintf("session:%s:%s:%s", testCompanyID, testAgentID, userID)
			connectionManager.RegisterConnection(sessionKeys[i], connections[i], testCompanyID, testAgentID)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Send messages to all connections
			event := eventGen.GenerateMessageEvent(testCompanyID, testAgentID, "memory_chat", fmt.Sprintf("memory_msg_%d", i))

			for connIndex := 0; connIndex < connectionCount; connIndex++ {
				connections[connIndex].WriteJSON(map[string]interface{}{
					"type": "memory_test",
					"data": event,
				})
			}
		}

		// Cleanup
		for i := 0; i < connectionCount; i++ {
			connectionManager.DeregisterConnection(sessionKeys[i])
		}

		serviceMetrics.UpdateConnectionMetrics(0, int64(connectionCount))
		serviceMetrics.UpdateMessageMetrics(int64(b.N*connectionCount), int64(b.N*connectionCount), 0)

		b.Logf("Memory pressure test - Connections: %d, Messages per iteration: %d", connectionCount, connectionCount)
	})
}
