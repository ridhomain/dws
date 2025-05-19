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
	HTTPPort int    `mapstructure:"http_port"`
	GRPCPort int    `mapstructure:"grpc_port"`
	PodID    string `mapstructure:"pod_id"` // Added for session management, expected from ENV (e.g., POD_IP via Downward API)
}

// NATSConfig holds NATS-related configurations.
type NATSConfig struct {
	URL          string `mapstructure:"url"`
	StreamName   string `mapstructure:"stream_name"`
	ConsumerName string `mapstructure:"consumer_name"`
}

// RedisConfig holds Redis-related configurations.
type RedisConfig struct {
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"` // Optional
	DB       int    `mapstructure:"db"`       // Optional
}

// LogConfig holds logging-related configurations.
type LogConfig struct {
	Level string `mapstructure:"level"`
}

// AuthConfig holds authentication-related configurations.
type AuthConfig struct {
	SecretToken               string `mapstructure:"secret_token"`               // Should primarily come from ENV
	TokenAESKey               string `mapstructure:"token_aes_key"`              // Should primarily come from ENV
	TokenGenerationAdminKey   string `mapstructure:"token_generation_admin_key"` // New: Key for /generate-token endpoint, from ENV
	TokenCacheTTLSeconds      int    `mapstructure:"token_cache_ttl_seconds"`
	AdminTokenAESKey          string `mapstructure:"admin_token_aes_key"`           // For admin token encryption
	AdminTokenCacheTTLSeconds int    `mapstructure:"admin_token_cache_ttl_seconds"` // TTL for cached admin tokens
}

// AppConfig holds application-specific configurations.
type AppConfig struct {
	ServiceName               string `mapstructure:"service_name"`
	Version                   string `mapstructure:"version"`
	PingIntervalSeconds       int    `mapstructure:"ping_interval_seconds"`
	ShutdownTimeoutSeconds    int    `mapstructure:"shutdown_timeout_seconds"`
	PongWaitSeconds           int    `mapstructure:"pong_wait_seconds"`
	WriteTimeoutSeconds       int    `mapstructure:"write_timeout_seconds"`
	MaxMissedPongs            int    `mapstructure:"max_missed_pongs"`
	SessionTTLSeconds         int    `mapstructure:"session_ttl_seconds"`
	RouteTTLSeconds           int    `mapstructure:"route_ttl_seconds"`
	TTLRefreshIntervalSeconds int    `mapstructure:"ttl_refresh_interval_seconds"`
	NATSMaxAckPending         int    `mapstructure:"nats_max_ack_pending"`
	SessionLockRetryDelayMs   int    `mapstructure:"session_lock_retry_delay_ms"` // Delay in milliseconds for session lock retry
}

// Config holds all configuration for the application.
type Config struct {
	Server ServerConfig `mapstructure:"server"`
	NATS   NATSConfig   `mapstructure:"nats"`
	Redis  RedisConfig  `mapstructure:"redis"`
	Log    LogConfig    `mapstructure:"log"`
	Auth   AuthConfig   `mapstructure:"auth"`
	App    AppConfig    `mapstructure:"app"`
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

	// Configure Viper to read from YAML file
	v.SetConfigName(os.Getenv("VIPER_CONFIG_NAME")) // e.g., "config"
	v.SetConfigType("yaml")
	v.AddConfigPath(os.Getenv("VIPER_CONFIG_PATH")) // e.g., "/app/config" or "./config" for local dev
	v.AddConfigPath(".")                            // Also look in current directory for local dev

	// Configure Viper to read from environment variables
	v.SetEnvPrefix(envPrefix)
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
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// InitializeViperForBootstrap sets up minimal viper for early stage needs like logger config.
// This is if you need a very basic logger *before* the full config provider is up.
// Generally, passing a pre-configured basic zap logger to NewViperProvider is preferred.
func InitializeViperForBootstrap() (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName(getEnv("VIPER_CONFIG_NAME", "config"))
	v.SetConfigType("yaml")
	v.AddConfigPath(getEnv("VIPER_CONFIG_PATH", "/app/config"))
	v.AddConfigPath(".")
	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read bootstrap config: %w", err)
		}
		// Config file not found is okay, will rely on ENV or defaults
	}
	return v, nil
}
