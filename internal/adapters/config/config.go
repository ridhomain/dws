package config

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const envPrefix = "DAISI_WS"

// ServerConfig holds server-related configurations.
// Note: Fields should be exported (start with uppercase) to be unmarshalled by Viper.
type ServerConfig struct {
	HTTPPort         int    `mapstructure:"http_port"`
	GRPCPort         int    `mapstructure:"grpc_port"`
	PodID            string `mapstructure:"pod_id"`            // Added for session management, expected from ENV (e.g., POD_IP via Downward API)
	EnableReflection bool   `mapstructure:"enable_reflection"` // For gRPC server reflection
}

// NATSConfig holds NATS-related configurations.
type NATSConfig struct {
	URL                   string `mapstructure:"url"`
	StreamName            string `mapstructure:"stream_name"`
	ConsumerName          string `mapstructure:"consumer_name"`
	ConnectTimeoutSeconds int    `mapstructure:"connect_timeout_seconds"`
	ReconnectWaitSeconds  int    `mapstructure:"reconnect_wait_seconds"`
	MaxReconnects         int    `mapstructure:"max_reconnects"`
	PingIntervalSeconds   int    `mapstructure:"ping_interval_seconds"`
	MaxPingsOut           int    `mapstructure:"max_pings_out"`
	RetryOnFailedConnect  bool   `mapstructure:"retry_on_failed_connect"`
}

// RedisConfig holds Redis-related configurations.
type RedisConfig struct {
	Address                                string `mapstructure:"address"`
	Password                               string `mapstructure:"password"` // Optional
	DB                                     int    `mapstructure:"db"`       // Optional
	WebsocketCompressionMode               string `mapstructure:"websocket_compression_mode"`
	WebsocketCompressionThreshold          int    `mapstructure:"websocket_compression_threshold"`
	WebsocketDevelopmentInsecureSkipVerify bool   `mapstructure:"websocket_development_insecure_skip_verify"`
}

// LogConfig holds logging-related configurations.
type LogConfig struct {
	Level string `mapstructure:"level"`
}

// AuthConfig holds authentication-related configurations.
type AuthConfig struct {
	SecretToken               string `mapstructure:"secret_token"`  // Should primarily come from ENV
	TokenAESKey               string `mapstructure:"token_aes_key"` // Should primarily come from ENV
	AdminSecretToken          string `mapstructure:"admin_secret_token"`
	AdminTokenAESKey          string `mapstructure:"admin_token_aes_key"` // For admin token encryption
	TokenCacheTTLSeconds      int    `mapstructure:"token_cache_ttl_seconds"`
	AdminTokenCacheTTLSeconds int    `mapstructure:"admin_token_cache_ttl_seconds"` // TTL for cached admin tokens
}

// AppConfig holds application-specific configurations.
type AppConfig struct {
	ServiceName                              string `mapstructure:"service_name"`
	Version                                  string `mapstructure:"version"`
	UseMelodyWebsocket                       bool   `mapstructure:"use_melody_websocket"`
	PingIntervalSeconds                      int    `mapstructure:"ping_interval_seconds"`
	ShutdownTimeoutSeconds                   int    `mapstructure:"shutdown_timeout_seconds"`
	PongWaitSeconds                          int    `mapstructure:"pong_wait_seconds"`
	WriteTimeoutSeconds                      int    `mapstructure:"write_timeout_seconds"`
	MaxMissedPongs                           int    `mapstructure:"max_missed_pongs"`
	SessionTTLSeconds                        int    `mapstructure:"session_ttl_seconds"`
	RouteTTLSeconds                          int    `mapstructure:"route_ttl_seconds"`
	TTLRefreshIntervalSeconds                int    `mapstructure:"ttl_refresh_interval_seconds"`
	NATSMaxAckPending                        int    `mapstructure:"nats_max_ack_pending"`
	SessionLockRetryDelayMs                  int    `mapstructure:"session_lock_retry_delay_ms"`
	NatsAckWaitSeconds                       int    `mapstructure:"nats_ack_wait_seconds"`
	GRPCCLientForwardTimeoutSeconds          int    `mapstructure:"grpc_client_forward_timeout_seconds"`
	ReadTimeoutSeconds                       int    `mapstructure:"read_timeout_seconds"`
	IdleTimeoutSeconds                       int    `mapstructure:"idle_timeout_seconds"`
	WebsocketCompressionMode                 string `mapstructure:"websocket_compression_mode"`
	WebsocketCompressionThreshold            int    `mapstructure:"websocket_compression_threshold"`
	WebsocketDevelopmentInsecureSkipVerify   bool   `mapstructure:"websocket_development_insecure_skip_verify"`
	GrpcPoolIdleTimeoutSeconds               int    `mapstructure:"grpc_pool_idle_timeout_seconds"`
	GrpcPoolHealthCheckIntervalSeconds       int    `mapstructure:"grpc_pool_health_check_interval_seconds"`
	GrpcCircuitBreakerFailThreshold          int    `mapstructure:"grpc_circuitbreaker_fail_threshold"`
	GrpcCircuitBreakerOpenDurationSeconds    int    `mapstructure:"grpc_circuitbreaker_open_duration_seconds"`
	WebsocketMessageBufferSize               int    `mapstructure:"websocket_message_buffer_size"`
	WebsocketBackpressureDropPolicy          string `mapstructure:"websocket_backpressure_drop_policy"` // e.g., "drop_oldest", "block"
	WebsocketSlowClientLatencyMs             int    `mapstructure:"websocket_slow_client_latency_ms"`
	WebsocketSlowClientDisconnectThresholdMs int    `mapstructure:"websocket_slow_client_disconnect_threshold_ms"`
}

type AdaptiveTTLRules struct {
	Enabled                  bool `mapstructure:"enabled"`
	MinTTLSeconds            int  `mapstructure:"min_ttl_seconds"`
	MaxTTLSeconds            int  `mapstructure:"max_ttl_seconds"`
	ActivityThresholdSeconds int  `mapstructure:"activity_threshold_seconds"` // If last_active is within this, consider active
	ActiveTTLSeconds         int  `mapstructure:"active_ttl_seconds"`         // TTL to set if active
	InactiveTTLSeconds       int  `mapstructure:"inactive_ttl_seconds"`       // TTL to set if inactive
}

type AdaptiveTTLConfig struct {
	SessionLock  AdaptiveTTLRules `mapstructure:"session_lock"`
	MessageRoute AdaptiveTTLRules `mapstructure:"message_route"`
	ChatRoute    AdaptiveTTLRules `mapstructure:"chat_route"`
}

// Config holds all configuration for the application.
type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	NATS        NATSConfig        `mapstructure:"nats"`
	Redis       RedisConfig       `mapstructure:"redis"`
	Log         LogConfig         `mapstructure:"log"`
	Auth        AuthConfig        `mapstructure:"auth"`
	App         AppConfig         `mapstructure:"app"`
	AdaptiveTTL AdaptiveTTLConfig `mapstructure:"adaptive_ttl"`
}

// Provider defines an interface for accessing application configuration.
// This allows for easy mocking in tests and decouples the app from Viper.
type Provider interface {
	Get() *Config
	// Add more specific getters if needed, e.g., GetServerConfig() ServerConfig
}

// viperProvider implements the Provider interface using Viper.
type viperProvider struct {
	config *Config
	logger *zap.Logger // Using zap.Logger directly for config internal logging, not domain.Logger to avoid circular deps
}

// NewViperProvider creates and initializes a new configuration provider using Viper.
// It loads configuration from file and environment variables, and sets up hot-reloading.
// A basic logger (e.g., zap.NewExample()) should be passed for internal logging during setup.
// appCtx is the application lifecycle context used for graceful shutdown of background tasks.
func NewViperProvider(appCtx context.Context, logger *zap.Logger) (Provider, error) {
	cfg := &Config{}
	v := viper.New()

	// Set default values (optional, but good practice)
	// v.SetDefault("server.http_port", 8080)
	// v.SetDefault("log.level", "info")
	v.SetDefault("app.session_ttl_seconds", 30)          // Default session TTL to 30 seconds as per TRD/PRD
	v.SetDefault("app.route_ttl_seconds", 60)            // Example: keeping other defaults, adjust as necessary
	v.SetDefault("app.ttl_refresh_interval_seconds", 10) // Example: keeping other defaults

	// Defaults for Adaptive TTL for SessionLock to align with 30s fixed requirement if not overridden
	// By default, we can disable adaptive TTL for session locks to ensure the 30s fixed value is used.
	// If adaptive TTL is operationally enabled, its MaxTTLSeconds should also be reviewed (e.g., set to 30).
	v.SetDefault("adaptive_ttl.session_lock.enabled", false)
	v.SetDefault("adaptive_ttl.session_lock.min_ttl_seconds", 15)             // Example: sensible if adaptive were enabled
	v.SetDefault("adaptive_ttl.session_lock.max_ttl_seconds", 30)             // Default to 30s if adaptive enabled
	v.SetDefault("adaptive_ttl.session_lock.activity_threshold_seconds", 120) // Example
	v.SetDefault("adaptive_ttl.session_lock.active_ttl_seconds", 30)          // Example
	v.SetDefault("adaptive_ttl.session_lock.inactive_ttl_seconds", 15)        // Example

	// Configure Viper to read from YAML file
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./config")
	v.AddConfigPath(".") // Also look in current directory for local dev
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./config")
	v.AddConfigPath(".") // For local dev

	// Configure Viper to read from environment variables
	// v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_")) // e.g., server.http_port becomes SERVER_HTTP_PORT

	// Attempt to read the configuration file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Warn("Config file not found; relying on defaults and environment variables", zap.Error(err))
		} else {
			logger.Error("Failed to read config file", zap.Error(err))
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Unmarshal the configuration into the struct
	if err := v.Unmarshal(cfg); err != nil {
		logger.Error("Failed to unmarshal config", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	p := &viperProvider{
		config: cfg,
		logger: logger,
	}

	// Set up SIGHUP for hot-reloading configuration
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.logger.Error("Panic recovered in SIGHUP handler goroutine",
					zap.String("goroutine_name", "SIGHUPConfigReloader"),
					zap.Any("panic_info", r),
					zap.String("stacktrace", string(debug.Stack())),
				)
			}
		}()
		p.logger.Info("SIGHUPConfigReloader goroutine started.")
		for {
			select {
			case sig := <-sigChan:
				p.logger.Info("SIGHUP received, attempting to reload configuration...", zap.String("signal", sig.String()))
				if err := v.ReadInConfig(); err != nil {
					p.logger.Error("Failed to re-read config file on SIGHUP", zap.Error(err))
				} else {
					newCfg := &Config{}
					if err := v.Unmarshal(newCfg); err != nil {
						p.logger.Error("Failed to unmarshal re-read config on SIGHUP", zap.Error(err))
					} else {
						p.config = newCfg
						p.logger.Info("Configuration reloaded successfully via SIGHUP")
					}
				}
			case <-appCtx.Done():
				p.logger.Info("SIGHUPConfigReloader goroutine shutting down due to context cancellation.")
				return // Exit goroutine when application context is done
			}
		}
	}()

	// Optional: Watch for config file changes (useful for local dev, less so in containers usually)
	v.WatchConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
		defer func() {
			if r := recover(); r != nil {
				p.logger.Error("Panic recovered in OnConfigChange callback",
					zap.String("event_name", e.Name),
					zap.String("event_op", e.Op.String()),
					zap.Any("panic_info", r),
					zap.String("stacktrace", string(debug.Stack())),
				)
			}
		}()
		p.logger.Info("Config file changed", zap.String("name", e.Name), zap.String("op", e.Op.String()))
		newCfg := &Config{}
		if err := v.Unmarshal(newCfg); err != nil {
			p.logger.Error("Failed to unmarshal config on file change event", zap.Error(err))
		} else {
			p.config = newCfg
			p.logger.Info("Configuration reloaded successfully via file change event")
		}
	})

	p.logger.Info("Configuration loaded successfully", zap.String("config_file_used", v.ConfigFileUsed()))

	return p, nil
}

// Get returns the current configuration.
func (p *viperProvider) Get() *Config {
	return p.config
}

// Helper function to get Viper env vars correctly for bootstrap if needed
// func getEnv(key, fallback string) string {
// 	if value, exists := os.LookupEnv(key); exists {
// 		return value
// 	}
// 	return fallback
// }
