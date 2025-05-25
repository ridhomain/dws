package mocks

import (
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
)

// MockConfigProvider implements config.Provider for benchmarking
type MockConfigProvider struct {
	config *config.Config
}

// NewMockConfigProvider creates a new mock config provider with benchmark settings
func NewMockConfigProvider() *MockConfigProvider {
	return &MockConfigProvider{
		config: &config.Config{
			Server: config.ServerConfig{
				HTTPPort:         0, // Random port
				GRPCPort:         0, // Random port
				PodID:            "benchmark-test-pod",
				EnableReflection: false,
			},
			NATS: config.NATSConfig{
				URL:                   "nats://mock-nats:4222",
				StreamName:            "wa_stream",
				ConsumerName:          "ws_fanout",
				ConnectTimeoutSeconds: 1,
				ReconnectWaitSeconds:  1,
				MaxReconnects:         1,
				PingIntervalSeconds:   10,
				MaxPingsOut:           1,
				RetryOnFailedConnect:  false,
			},
			Redis: config.RedisConfig{
				Address:  "mock-redis:6379",
				Password: "",
				DB:       0,
			},
			Log: config.LogConfig{
				Level: "error", // Minimize I/O overhead during benchmarks
			},
			Auth: config.AuthConfig{
				SecretToken:               "benchmark-secret-token-32chars123",
				TokenAESKey:               "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				AdminSecretToken:          "benchmark-admin-secret-32chars",
				AdminTokenAESKey:          "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
				TokenCacheTTLSeconds:      30,
				AdminTokenCacheTTLSeconds: 60,
			},
			App: config.AppConfig{
				ServiceName:                              "daisi-ws-service-benchmark",
				Version:                                  "test",
				PingIntervalSeconds:                      5,
				ShutdownTimeoutSeconds:                   1,
				PongWaitSeconds:                          10,
				WriteTimeoutSeconds:                      5,
				MaxMissedPongs:                           1,
				SessionTTLSeconds:                        30,
				RouteTTLSeconds:                          300,
				TTLRefreshIntervalSeconds:                10,
				NATSMaxAckPending:                        1000,
				SessionLockRetryDelayMs:                  10,
				NatsAckWaitSeconds:                       1,
				GRPCCLientForwardTimeoutSeconds:          1,
				ReadTimeoutSeconds:                       1,
				IdleTimeoutSeconds:                       5,
				WebsocketCompressionMode:                 "disabled",
				WebsocketCompressionThreshold:            1024,
				WebsocketDevelopmentInsecureSkipVerify:   false,
				GrpcPoolIdleTimeoutSeconds:               30,
				GrpcPoolHealthCheckIntervalSeconds:       10,
				GrpcCircuitBreakerFailThreshold:          5,
				GrpcCircuitBreakerOpenDurationSeconds:    30,
				WebsocketMessageBufferSize:               100,
				WebsocketBackpressureDropPolicy:          "drop_oldest",
				WebsocketSlowClientLatencyMs:             1000,
				WebsocketSlowClientDisconnectThresholdMs: 5000,
			},
		},
	}
}

// Get implements config.Provider
func (m *MockConfigProvider) Get() *config.Config {
	return m.config
}

// UpdateConfig allows updating config during tests
func (m *MockConfigProvider) UpdateConfig(cfg *config.Config) {
	m.config = cfg
}
