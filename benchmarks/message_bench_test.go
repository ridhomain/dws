package benchmarks

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/mocks"
	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/utils"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// setupMessageBenchmark creates a test environment for message processing benchmarks
func setupMessageBenchmark(b *testing.B) (*mocks.MockNatsConsumer, *utils.WebSocketClientPool, *utils.EventPayloadGenerator, *utils.ServiceMetrics) {
	b.Helper()

	// Create mock NATS consumer
	natsConsumer := mocks.NewMockNatsConsumer()

	// Create WebSocket client pool for testing
	wsPool := utils.NewWebSocketClientPool()

	// Create event payload generator
	eventGen := utils.NewEventPayloadGenerator()

	// Create service metrics tracker
	serviceMetrics := utils.NewServiceMetrics()

	return natsConsumer, wsPool, eventGen, serviceMetrics
}

// BenchmarkNATSMessageProcessing tests NATS message processing performance
func BenchmarkNATSMessageProcessing(b *testing.B) {
	natsConsumer, _, eventGen, serviceMetrics := setupMessageBenchmark(b)

	ctx := context.Background()

	// Create a simple message handler for testing
	messageHandler := func(msg *nats.Msg) {
		var payload domain.EnrichedEventPayload
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			return
		}
		// Simulate processing work
		serviceMetrics.UpdateMessageMetrics(0, 1, 0)
	}

	b.Run("SingleMessageProcessing", func(b *testing.B) {
		// Subscribe to a test subject
		sub, err := natsConsumer.SubscribeToChats(ctx, testCompanyID, testAgentID, messageHandler)
		if err != nil {
			b.Fatalf("Failed to subscribe: %v", err)
		}
		defer sub.Drain()

		// Generate test events
		events := make([][]byte, b.N)
		for i := 0; i < b.N; i++ {
			event := eventGen.GenerateChatEvent(testCompanyID, testAgentID, fmt.Sprintf("chat_%d", i))
			events[i], _ = eventGen.SerializeEvent(event)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			subject := fmt.Sprintf("chats.%s.%s", testCompanyID, testAgentID)
			natsConsumer.InjectMessage(subject, events[i])
		}

		// Wait a brief moment for message processing
		time.Sleep(10 * time.Millisecond)
	})

	b.Run("BulkMessageProcessing", func(b *testing.B) {
		scales := []int{10, 100, 1000}

		for _, scale := range scales {
			b.Run(fmt.Sprintf("Scale_%d", scale), func(b *testing.B) {
				// Subscribe to test subject
				sub, err := natsConsumer.SubscribeToChats(ctx, testCompanyID, testAgentID, messageHandler)
				if err != nil {
					b.Fatalf("Failed to subscribe at scale %d: %v", scale, err)
				}
				defer sub.Drain()

				// Generate bulk events
				bulkEvents := eventGen.GenerateBulkEvents(scale, testCompanyID, testAgentID)
				serializedEvents := make([][]byte, len(bulkEvents))
				for i, event := range bulkEvents {
					serializedEvents[i], _ = eventGen.SerializeEvent(event)
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					eventIndex := i % scale
					subject := fmt.Sprintf("chats.%s.%s", testCompanyID, testAgentID)
					natsConsumer.InjectMessage(subject, serializedEvents[eventIndex])
				}

				serviceMetrics.UpdateMessageMetrics(0, int64(scale), 0)
			})
		}
	})

	b.Run("ConcurrentMessageProcessing", func(b *testing.B) {
		// Subscribe to test subject
		sub, err := natsConsumer.SubscribeToChats(ctx, testCompanyID, testAgentID, messageHandler)
		if err != nil {
			b.Fatalf("Failed to subscribe for concurrent test: %v", err)
		}
		defer sub.Drain()

		// Pre-generate events
		events := eventGen.GenerateBulkEvents(1000, testCompanyID, testAgentID)
		serializedEvents := make([][]byte, len(events))
		for i, event := range events {
			serializedEvents[i], _ = eventGen.SerializeEvent(event)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			eventIndex := 0
			for pb.Next() {
				subject := fmt.Sprintf("chats.%s.%s", testCompanyID, testAgentID)
				natsConsumer.InjectMessage(subject, serializedEvents[eventIndex%len(serializedEvents)])
				serviceMetrics.UpdateMessageMetrics(0, 1, 0)
				eventIndex++
			}
		})

		// Wait for processing to complete
		time.Sleep(50 * time.Millisecond)
	})

	b.Run("JSONUnmarshalingOverhead", func(b *testing.B) {
		// Test the overhead of JSON unmarshaling specifically
		event := eventGen.GenerateChatEvent(testCompanyID, testAgentID, "test_chat")
		eventData, _ := eventGen.SerializeEvent(event)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var payload domain.EnrichedEventPayload
			err := json.Unmarshal(eventData, &payload)
			if err != nil {
				b.Errorf("JSON unmarshal failed: %v", err)
			}
		}
	})
}

// BenchmarkWebSocketBroadcast tests message broadcasting to multiple connections
func BenchmarkWebSocketBroadcast(b *testing.B) {
	_, wsPool, eventGen, serviceMetrics := setupMessageBenchmark(b)

	// Create test tokens for connections
	batchGen, err := utils.NewBatchTokenGenerator(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	)
	if err != nil {
		b.Fatalf("Failed to create batch token generator: %v", err)
	}

	b.Run("SingleConnectionBroadcast", func(b *testing.B) {
		// Create one connection
		tokens, _ := batchGen.GenerateUserTokens(1, testCompanyID, testAgentID, time.Hour)
		err := wsPool.CreateBulkConnections(1, testCompanyID, testAgentID, tokens, 100, utils.BackpressureDrop)
		if err != nil {
			b.Fatalf("Failed to create test connection: %v", err)
		}

		// Generate test message
		event := eventGen.GenerateChatEvent(testCompanyID, testAgentID, "broadcast_test")
		messageData, _ := eventGen.SerializeEvent(event)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := wsPool.BroadcastMessage(messageData)
			if err != nil {
				b.Errorf("Broadcast failed: %v", err)
			}
			serviceMetrics.UpdateMessageMetrics(1, 0, 0)
		}

		wsPool.CloseAllConnections()
	})

	b.Run("MultipleConnectionBroadcast", func(b *testing.B) {
		scales := []int{10, 100, 500}

		for _, scale := range scales {
			b.Run(fmt.Sprintf("Scale_%d_connections", scale), func(b *testing.B) {
				// Create multiple connections
				tokens, _ := batchGen.GenerateUserTokens(scale, testCompanyID, testAgentID, time.Hour)
				err := wsPool.CreateBulkConnections(scale, testCompanyID, testAgentID, tokens, 100, utils.BackpressureDrop)
				if err != nil {
					b.Fatalf("Failed to create %d test connections: %v", scale, err)
				}

				// Generate test message
				event := eventGen.GenerateChatEvent(testCompanyID, testAgentID, "broadcast_scale_test")
				messageData, _ := eventGen.SerializeEvent(event)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					err := wsPool.BroadcastMessage(messageData)
					if err != nil {
						b.Errorf("Broadcast failed at scale %d: %v", scale, err)
					}
					serviceMetrics.UpdateMessageMetrics(int64(scale), 0, 0)
				}

				wsPool.CloseAllConnections()
				b.Logf("Broadcast to %d connections completed", scale)
			})
		}
	})

	b.Run("BufferOverflowSimulation", func(b *testing.B) {
		// Create connections with small buffers to test overflow
		tokens, _ := batchGen.GenerateUserTokens(10, testCompanyID, testAgentID, time.Hour)
		err := wsPool.CreateBulkConnections(10, testCompanyID, testAgentID, tokens, 5, utils.BackpressureDrop)
		if err != nil {
			b.Fatalf("Failed to create test connections for overflow test: %v", err)
		}

		// Generate large message
		event := eventGen.GenerateChatEvent(testCompanyID, testAgentID, "overflow_test")
		messageData, _ := eventGen.SerializeEvent(event)

		var droppedCount int64

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Send many messages rapidly to cause buffer overflow
			for j := 0; j < 20; j++ {
				err := wsPool.BroadcastMessage(messageData)
				if err != nil {
					droppedCount++
				}
			}
		}

		serviceMetrics.UpdateMessageMetrics(0, 0, droppedCount)
		wsPool.CloseAllConnections()
		b.Logf("Buffer overflow test completed, dropped messages: %d", droppedCount)
	})
}

// BenchmarkClientMessageProcessing tests processing of client messages
func BenchmarkClientMessageProcessing(b *testing.B) {
	_, wsPool, _, serviceMetrics := setupMessageBenchmark(b)

	// Create test tokens
	batchGen, err := utils.NewBatchTokenGenerator(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	)
	if err != nil {
		b.Fatalf("Failed to create batch token generator: %v", err)
	}

	b.Run("SelectChatMessageProcessing", func(b *testing.B) {
		// Create test connection
		tokens, _ := batchGen.GenerateUserTokens(1, testCompanyID, testAgentID, time.Hour)
		err := wsPool.CreateBulkConnections(1, testCompanyID, testAgentID, tokens, 100, utils.BackpressureDrop)
		if err != nil {
			b.Fatalf("Failed to create test connection: %v", err)
		}

		// Create select_chat message
		selectChatMsg := map[string]interface{}{
			"action":  "select_chat",
			"chat_id": "test_chat_123",
		}
		msgData, _ := json.Marshal(selectChatMsg)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Simulate processing select_chat message
			var message map[string]interface{}
			err := json.Unmarshal(msgData, &message)
			if err != nil {
				b.Errorf("Failed to unmarshal select_chat message: %v", err)
			}

			// Simulate route update logic
			if action, ok := message["action"].(string); ok && action == "select_chat" {
				serviceMetrics.UpdateMessageMetrics(0, 1, 0)
			}
		}

		wsPool.CloseAllConnections()
	})

	b.Run("ConcurrentClientMessages", func(b *testing.B) {
		// Create multiple connections
		const connectionCount = 50
		tokens, _ := batchGen.GenerateUserTokens(connectionCount, testCompanyID, testAgentID, time.Hour)
		err := wsPool.CreateBulkConnections(connectionCount, testCompanyID, testAgentID, tokens, 100, utils.BackpressureDrop)
		if err != nil {
			b.Fatalf("Failed to create test connections: %v", err)
		}

		// Create different types of client messages
		messages := []map[string]interface{}{
			{"action": "select_chat", "chat_id": "chat_1"},
			{"action": "select_chat", "chat_id": "chat_2"},
			{"action": "ping"},
			{"action": "heartbeat"},
		}

		serializedMessages := make([][]byte, len(messages))
		for i, msg := range messages {
			serializedMessages[i], _ = json.Marshal(msg)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			msgIndex := 0
			for pb.Next() {
				msgData := serializedMessages[msgIndex%len(serializedMessages)]

				// Simulate message processing
				var message map[string]interface{}
				err := json.Unmarshal(msgData, &message)
				if err == nil {
					serviceMetrics.UpdateMessageMetrics(0, 1, 0)
				}

				msgIndex++
			}
		})

		wsPool.CloseAllConnections()
	})

	b.Run("MessageRoutingDecision", func(b *testing.B) {
		// Test the overhead of routing decisions
		routingMessages := []map[string]interface{}{
			{"action": "select_chat", "chat_id": "chat_1", "company_id": testCompanyID, "agent_id": testAgentID},
			{"action": "select_chat", "chat_id": "chat_2", "company_id": testCompanyID, "agent_id": testAgentID},
			{"action": "select_chat", "chat_id": "chat_3", "company_id": testCompanyID, "agent_id": testAgentID},
		}

		serializedMessages := make([][]byte, len(routingMessages))
		for i, msg := range routingMessages {
			serializedMessages[i], _ = json.Marshal(msg)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			msgData := serializedMessages[i%len(serializedMessages)]

			var message map[string]interface{}
			err := json.Unmarshal(msgData, &message)
			if err != nil {
				b.Errorf("Failed to unmarshal routing message: %v", err)
				continue
			}

			// Simulate routing decision logic
			if action, ok := message["action"].(string); ok {
				switch action {
				case "select_chat":
					if chatID, ok := message["chat_id"].(string); ok && chatID != "" {
						// Simulate route registration/update
						serviceMetrics.UpdateMessageMetrics(0, 1, 0)
					}
				case "ping", "heartbeat":
					// No routing needed
					serviceMetrics.UpdateMessageMetrics(0, 1, 0)
				}
			}
		}
	})
}

// BenchmarkMessageEndToEnd tests complete message pipeline
func BenchmarkMessageEndToEnd(b *testing.B) {
	natsConsumer, wsPool, eventGen, serviceMetrics := setupMessageBenchmark(b)

	ctx := context.Background()

	// Create test connections
	batchGen, err := utils.NewBatchTokenGenerator(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	)
	if err != nil {
		b.Fatalf("Failed to create batch token generator: %v", err)
	}

	b.Run("EndToEndMessageFlow", func(b *testing.B) {
		// Create connections
		tokens, _ := batchGen.GenerateUserTokens(10, testCompanyID, testAgentID, time.Hour)
		err := wsPool.CreateBulkConnections(10, testCompanyID, testAgentID, tokens, 100, utils.BackpressureDrop)
		if err != nil {
			b.Fatalf("Failed to create test connections: %v", err)
		}

		// Create message handler that forwards to WebSocket
		messageHandler := func(msg *nats.Msg) {
			var payload domain.EnrichedEventPayload
			if err := json.Unmarshal(msg.Data, &payload); err != nil {
				return
			}

			// Simulate forwarding to WebSocket connections
			forwardData, _ := json.Marshal(payload)
			wsPool.BroadcastMessage(forwardData)
			serviceMetrics.UpdateMessageMetrics(1, 1, 0)
		}

		// Subscribe to NATS
		sub, err := natsConsumer.SubscribeToChats(ctx, testCompanyID, testAgentID, messageHandler)
		if err != nil {
			b.Fatalf("Failed to subscribe: %v", err)
		}
		defer sub.Drain()

		// Generate test events
		events := eventGen.GenerateBulkEvents(100, testCompanyID, testAgentID)
		serializedEvents := make([][]byte, len(events))
		for i, event := range events {
			serializedEvents[i], _ = eventGen.SerializeEvent(event)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eventIndex := i % len(events)
			subject := fmt.Sprintf("chats.%s.%s", testCompanyID, testAgentID)

			// 1. NATS message received
			natsConsumer.InjectMessage(subject, serializedEvents[eventIndex])

			// 2. Message processing and WebSocket forwarding happens in handler
			// (simulated above)
		}

		// Wait for processing
		time.Sleep(100 * time.Millisecond)
		wsPool.CloseAllConnections()
	})

	b.Run("ConcurrentEndToEndFlow", func(b *testing.B) {
		// Create more connections for concurrent test
		tokens, _ := batchGen.GenerateUserTokens(50, testCompanyID, testAgentID, time.Hour)
		err := wsPool.CreateBulkConnections(50, testCompanyID, testAgentID, tokens, 100, utils.BackpressureDrop)
		if err != nil {
			b.Fatalf("Failed to create concurrent test connections: %v", err)
		}

		var processedCount int64
		var mu sync.Mutex

		messageHandler := func(msg *nats.Msg) {
			var payload domain.EnrichedEventPayload
			if err := json.Unmarshal(msg.Data, &payload); err != nil {
				return
			}

			forwardData, _ := json.Marshal(payload)
			wsPool.BroadcastMessage(forwardData)

			mu.Lock()
			processedCount++
			mu.Unlock()

			serviceMetrics.UpdateMessageMetrics(1, 1, 0)
		}

		sub, err := natsConsumer.SubscribeToChats(ctx, testCompanyID, testAgentID, messageHandler)
		if err != nil {
			b.Fatalf("Failed to subscribe for concurrent test: %v", err)
		}
		defer sub.Drain()

		events := eventGen.GenerateBulkEvents(200, testCompanyID, testAgentID)
		serializedEvents := make([][]byte, len(events))
		for i, event := range events {
			serializedEvents[i], _ = eventGen.SerializeEvent(event)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			eventIndex := 0
			for pb.Next() {
				subject := fmt.Sprintf("chats.%s.%s", testCompanyID, testAgentID)
				natsConsumer.InjectMessage(subject, serializedEvents[eventIndex%len(serializedEvents)])
				eventIndex++
			}
		})

		// Wait for processing
		time.Sleep(200 * time.Millisecond)

		mu.Lock()
		finalProcessedCount := processedCount
		mu.Unlock()

		wsPool.CloseAllConnections()
		b.Logf("Concurrent end-to-end flow processed %d messages", finalProcessedCount)
	})
}
