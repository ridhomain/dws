This file is a merged representation of the entire codebase, combined into a single document by Repomix.
The content has been processed where comments have been removed, empty lines have been removed, content has been formatted for parsing in markdown style.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
4. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Code comments have been removed from supported file types
- Empty lines have been removed from all files
- Content has been formatted for parsing in markdown style
- Files are sorted by Git change count (files with more changes are at the bottom)

## Additional Info

# Directory Structure
```
cmd/
  daisi-ws-service/
    main.go
config/
  config.yaml
internal/
  adapters/
    config/
      config.go
    http/
      admin_handlers.go
    logger/
      zap_adapter.go
    metrics/
      prometheus_adapter.go
    middleware/
      admin_auth.go
      auth.go
    nats/
      consumer.go
    redis/
      admin_token_cache_adapter.go
      kill_switch_pubsub.go
      session_lock_manager.go
    websocket/
      admin_handler.go
      conn.go
      handler.go
      protocol.go
      router.go
  application/
    auth_service.go
    connection_manager.go
    connection_registry.go
    kill_switch.go
    session_locking.go
    session_renewal.go
  bootstrap/
    app.go
    providers.go
    wire_gen.go
    wire.go
  domain/
    auth.go
    cache.go
    errors.go
    logger.go
    nats_payloads.go
    session.go
    websocket.go
pkg/
  contextkeys/
    keys.go
  crypto/
    aesgcm.go
    hash.go
  rediskeys/
    keys.go
  safego/
    safego.go
.gitignore
Dockerfile
go.mod
```

# Files

## File: internal/adapters/http/admin_handlers.go
```go
package http
import (
	"encoding/json"
	"net/http"
	"time"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
)
type GenerateTokenRequest struct {
	CompanyID        string `json:"company_id"`
	AgentID          string `json:"agent_id"`
	UserID           string `json:"user_id"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}
type GenerateTokenResponse struct {
	Token string `json:"token"`
}
func GenerateTokenHandler(cfgProvider config.Provider, logger domain.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			logger.Warn(r.Context(), "Invalid method for /generate-token", "method", r.Method)
			domain.NewErrorResponse(domain.ErrMethodNotAllowed, "Method not allowed", "Only POST method is allowed.").WriteJSON(w, http.StatusMethodNotAllowed)
			return
		}
		var reqPayload GenerateTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
			logger.Warn(r.Context(), "Failed to decode /generate-token payload", "error", err.Error())
			domain.NewErrorResponse(domain.ErrBadRequest, "Invalid request payload", err.Error()).WriteJSON(w, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		if reqPayload.CompanyID == "" || reqPayload.AgentID == "" || reqPayload.UserID == "" || reqPayload.ExpiresInSeconds <= 0 {
			logger.Warn(r.Context(), "Invalid payload for /generate-token", "payload", reqPayload)
			domain.NewErrorResponse(domain.ErrBadRequest, "Invalid payload", "company_id, agent_id, user_id, and positive expires_in_seconds are required.").WriteJSON(w, http.StatusBadRequest)
			return
		}
		appCfg := cfgProvider.Get()
		if appCfg.Auth.TokenAESKey == "" {
			logger.Error(r.Context(), "TokenAESKey not configured for /generate-token")
			domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Token encryption key not configured.").WriteJSON(w, http.StatusInternalServerError)
			return
		}
		tokenAuthContext := domain.AuthenticatedUserContext{
			CompanyID: reqPayload.CompanyID,
			AgentID:   reqPayload.AgentID,
			UserID:    reqPayload.UserID,
			ExpiresAt: time.Now().Add(time.Duration(reqPayload.ExpiresInSeconds) * time.Second),
		}
		plaintextTokenPayload, err := json.Marshal(tokenAuthContext)
		if err != nil {
			logger.Error(r.Context(), "Failed to marshal token context for /generate-token", "error", err.Error())
			domain.NewErrorResponse(domain.ErrInternal, "Failed to create token", "Internal error during token generation.").WriteJSON(w, http.StatusInternalServerError)
			return
		}
		encryptedToken, err := crypto.EncryptAESGCM(appCfg.Auth.TokenAESKey, plaintextTokenPayload)
		if err != nil {
			logger.Error(r.Context(), "Failed to encrypt token for /generate-token", "error", err.Error())
			domain.NewErrorResponse(domain.ErrInternal, "Failed to create token", "Internal error during token encryption.").WriteJSON(w, http.StatusInternalServerError)
			return
		}
		resp := GenerateTokenResponse{Token: encryptedToken}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error(r.Context(), "Failed to encode /generate-token response", "error", err.Error())
		}
	}
}
```

## File: internal/adapters/logger/zap_adapter.go
```go
package logger
import (
	"context"
	"os"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)
type ZapAdapter struct {
	logger *zap.Logger
}
func NewZapAdapter(cfgProvider config.Provider, serviceName string) (domain.Logger, error) {
	appConfig := cfgProvider.Get()
	logLevel := appConfig.Log.Level
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(logLevel)); err != nil {
		zapLevel = zapcore.InfoLevel
	}
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.RFC3339NanoTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	infoLevel := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapLevel && lvl < zapcore.ErrorLevel
	})
	errorLevel := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapLevel && lvl >= zapcore.ErrorLevel
	})
	consoleInfo := zapcore.Lock(os.Stdout)
	consoleErrors := zapcore.Lock(os.Stderr)
	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), consoleInfo, infoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), consoleErrors, errorLevel),
	)
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	zapLogger = zapLogger.With(zap.String("service", serviceName))
	return &ZapAdapter{logger: zapLogger}, nil
}
func (za *ZapAdapter) extractFieldsFromContext(ctx context.Context, additionalFields []any) []zap.Field {
	fields := make([]zap.Field, 0, len(additionalFields)/2+5)
	if requestID, ok := ctx.Value(contextkeys.RequestIDKey).(string); ok && requestID != "" {
		fields = append(fields, zap.String(string(contextkeys.RequestIDKey), requestID))
	}
	if eventID, ok := ctx.Value(contextkeys.EventIDKey).(string); ok && eventID != "" {
		fields = append(fields, zap.String(string(contextkeys.EventIDKey), eventID))
	}
	if userID, ok := ctx.Value(contextkeys.UserIDKey).(string); ok && userID != "" {
		fields = append(fields, zap.String(string(contextkeys.UserIDKey), userID))
	}
	if companyID, ok := ctx.Value(contextkeys.CompanyIDKey).(string); ok && companyID != "" {
		fields = append(fields, zap.String(string(contextkeys.CompanyIDKey), companyID))
	}
	if agentID, ok := ctx.Value(contextkeys.AgentIDKey).(string); ok && agentID != "" {
		fields = append(fields, zap.String(string(contextkeys.AgentIDKey), agentID))
	}
	// Process additional fields (expecting key-value pairs)
	for i := 0; i < len(additionalFields); i += 2 {
		if i+1 < len(additionalFields) {
			key, okKey := additionalFields[i].(string)
			val := additionalFields[i+1]
			if okKey {
				fields = append(fields, zap.Any(key, val))
			} else {
				// If key is not a string, log it as an unknown field
				fields = append(fields, zap.Any(string("unknown_field_type_at_index_")+string(rune(i)), additionalFields[i]))
				fields = append(fields, zap.Any(string("unknown_field_value_at_index_")+string(rune(i+1)), val))
			}
		} else {
			fields = append(fields, zap.Any(string(" lẻ_field_at_index_")+string(rune(i)), additionalFields[i]))
		}
	}
	return fields
}
func (za *ZapAdapter) Debug(ctx context.Context, msg string, args ...any) {
	if !za.logger.Core().Enabled(zapcore.DebugLevel) {
		return
	}
	fields := za.extractFieldsFromContext(ctx, args)
	za.logger.Debug(msg, fields...)
}
func (za *ZapAdapter) Info(ctx context.Context, msg string, args ...any) {
	if !za.logger.Core().Enabled(zapcore.InfoLevel) {
		return
	}
	fields := za.extractFieldsFromContext(ctx, args)
	za.logger.Info(msg, fields...)
}
func (za *ZapAdapter) Warn(ctx context.Context, msg string, args ...any) {
	if !za.logger.Core().Enabled(zapcore.WarnLevel) {
		return
	}
	fields := za.extractFieldsFromContext(ctx, args)
	za.logger.Warn(msg, fields...)
}
func (za *ZapAdapter) Error(ctx context.Context, msg string, args ...any) {
	if !za.logger.Core().Enabled(zapcore.ErrorLevel) {
		return
	}
	fields := za.extractFieldsFromContext(ctx, args)
	za.logger.Error(msg, fields...)
}
func (za *ZapAdapter) Fatal(ctx context.Context, msg string, args ...any) {
	fields := za.extractFieldsFromContext(ctx, args)
	za.logger.Fatal(msg, fields...)
}
func (za *ZapAdapter) With(args ...any) domain.Logger {
	zapFields := make([]zap.Field, 0, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			key, okKey := args[i].(string)
			val := args[i+1]
			if okKey {
				zapFields = append(zapFields, zap.Any(key, val))
			} else {
				zapFields = append(zapFields, zap.Any("invalid_with_field_key", args[i]))
				zapFields = append(zapFields, zap.Any("invalid_with_field_value", val))
			}
		} else {
			zapFields = append(zapFields, zap.Any("invalid_with_field_orphan", args[i]))
		}
	}
	clonedLogger := za.logger.With(zapFields...)
	return &ZapAdapter{logger: clonedLogger}
}
```

## File: internal/adapters/metrics/prometheus_adapter.go
```go
package metrics
import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)
var (
	ActiveConnectionsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "dws_active_connections",
			Help: "Number of active WebSocket connections.",
		},
	)
)
func IncrementActiveConnections() {
	ActiveConnectionsGauge.Inc()
}
func DecrementActiveConnections() {
	ActiveConnectionsGauge.Dec()
}
```

## File: internal/adapters/redis/admin_token_cache_adapter.go
```go
package redis
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
type AdminTokenCacheAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
}
func NewAdminTokenCacheAdapter(redisClient *redis.Client, logger domain.Logger) *AdminTokenCacheAdapter {
	return &AdminTokenCacheAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}
func (a *AdminTokenCacheAdapter) Get(ctx context.Context, key string) (*domain.AdminUserContext, error) {
	val, err := a.redisClient.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		a.logger.Debug(ctx, "Admin token cache miss", "key", key)
		return nil, application.ErrCacheMiss
	}
	if err != nil {
		a.logger.Error(ctx, "Failed to get admin token from Redis cache", "key", key, "error", err.Error())
		return nil, fmt.Errorf("redis GET for admin token key '%s' failed: %w", key, err)
	}
	var adminCtx domain.AdminUserContext
	if err = json.Unmarshal([]byte(val), &adminCtx); err != nil {
		a.logger.Error(ctx, "Failed to unmarshal cached admin token data", "key", key, "error", err.Error())
		return nil, fmt.Errorf("failed to unmarshal admin token data for key '%s': %w", key, err)
	}
	a.logger.Debug(ctx, "Admin token cache hit", "key", key, "admin_id", adminCtx.AdminID)
	return &adminCtx, nil
}
func (a *AdminTokenCacheAdapter) Set(ctx context.Context, key string, value *domain.AdminUserContext, ttl time.Duration) error {
	payloadBytes, err := json.Marshal(value)
	if err != nil {
		a.logger.Error(ctx, "Failed to marshal admin token for caching", "key", key, "admin_id", value.AdminID, "error", err.Error())
		return fmt.Errorf("failed to marshal admin token for key '%s': %w", key, err)
	}
	if err = a.redisClient.Set(ctx, key, string(payloadBytes), ttl).Err(); err != nil {
		a.logger.Error(ctx, "Failed to set admin token in Redis cache", "key", key, "admin_id", value.AdminID, "error", err.Error())
		return fmt.Errorf("redis SET for admin token key '%s' failed: %w", key, err)
	}
	a.logger.Debug(ctx, "Successfully cached admin token", "key", key, "admin_id", value.AdminID, "ttl", ttl.String())
	return nil
}
```

## File: internal/adapters/redis/session_lock_manager.go
```go
package redis
import (
	"context"
	"errors"
	"fmt"
	"time"
	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
type SessionLockManagerAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
}
func NewSessionLockManagerAdapter(redisClient *redis.Client, logger domain.Logger) *SessionLockManagerAdapter {
	if redisClient == nil {
		logger.Error(context.Background(), "Redis client is nil in NewSessionLockManagerAdapter", "error", "nil_redis_client")
	}
	return &SessionLockManagerAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}
func (a *SessionLockManagerAdapter) AcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	acquired, err := a.redisClient.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		a.logger.Error(ctx, "Redis SETNX failed", "key", key, "error", err.Error())
		return false, fmt.Errorf("redis SETNX for key '%s' failed: %w", key, err)
	}
	a.logger.Info(ctx, "Redis SETNX result", "key", key, "value", value, "ttl", ttl, "acquired", acquired)
	return acquired, nil
}
func (a *SessionLockManagerAdapter) ReleaseLock(ctx context.Context, key string, value string) (bool, error) {
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`
	result, err := a.redisClient.Eval(ctx, script, []string{key}, value).Int64()
	if err != nil && !errors.Is(err, redis.Nil) {
		a.logger.Error(ctx, "Redis EVAL (ReleaseLock script) failed", "key", key, "value", value, "error", err.Error())
		return false, fmt.Errorf("redis EVAL for ReleaseLock on key '%s' failed: %w", key, err)
	}
	released := result == 1
	a.logger.Info(ctx, "Redis ReleaseLock result", "key", key, "value", value, "released_by_script", released, "script_result_val", result)
	return released, nil
}
func (a *SessionLockManagerAdapter) RefreshLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("expire", KEYS[1], ARGV[2])
		else
			return 0
		end
	`
	ttlSeconds := int64(ttl.Seconds())
	result, err := a.redisClient.Eval(ctx, script, []string{key}, value, ttlSeconds).Int64()
	if err != nil && !errors.Is(err, redis.Nil) {
		a.logger.Error(ctx, "Redis EVAL (RefreshLock script) failed", "key", key, "value", value, "error", err.Error())
		return false, fmt.Errorf("redis EVAL for RefreshLock on key '%s' failed: %w", key, err)
	}
	refreshed := result == 1
	a.logger.Info(ctx, "Redis RefreshLock result", "key", key, "value", value, "ttl_seconds", ttlSeconds, "refreshed_by_script", refreshed, "script_result_val", result)
	return refreshed, nil
}
func (a *SessionLockManagerAdapter) ForceAcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	_, err := a.redisClient.Set(ctx, key, value, ttl).Result()
	if err != nil {
		a.logger.Error(ctx, "Redis SET failed for ForceAcquireLock", "key", key, "error", err.Error())
		return false, fmt.Errorf("redis SET for key '%s' in ForceAcquireLock failed: %w", key, err)
	}
	a.logger.Info(ctx, "Redis SET successful for ForceAcquireLock", "key", key, "value", value, "ttl", ttl)
	return true, nil
}
```

## File: internal/adapters/websocket/conn.go
```go
package websocket
import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
type Connection struct {
	wsConn              *websocket.Conn
	logger              domain.Logger
	config              *config.AppConfig
	mu                  sync.Mutex
	lastPongTime        time.Time
	connCtx             context.Context
	cancelConnCtxFunc   context.CancelFunc
	writeTimeoutSeconds int
	pingIntervalSeconds int
	pongWaitSeconds     int
	remoteAddrStr       string
}
func NewConnection(
	connCtx context.Context,
	cancelFunc context.CancelFunc,
	wsConn *websocket.Conn,
	remoteAddr string,
	logger domain.Logger,
	cfgProvider config.Provider,
) *Connection {
	appCfg := cfgProvider.Get().App
	return &Connection{
		wsConn:              wsConn,
		logger:              logger,
		config:              &appCfg,
		lastPongTime:        time.Now(),
		connCtx:             connCtx,
		cancelConnCtxFunc:   cancelFunc,
		writeTimeoutSeconds: appCfg.WriteTimeoutSeconds,
		pingIntervalSeconds: appCfg.PingIntervalSeconds,
		pongWaitSeconds:     appCfg.PongWaitSeconds,
		remoteAddrStr:       remoteAddr,
	}
}
func (c *Connection) Context() context.Context {
	return c.connCtx
}
func (c *Connection) Close(statusCode websocket.StatusCode, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelConnCtxFunc != nil {
		c.cancelConnCtxFunc()
	}
	return c.wsConn.Close(statusCode, reason)
}
func (c *Connection) WriteJSON(v interface{}) error {
	payload, err := json.Marshal(v)
	if err != nil {
		c.logger.Error(c.connCtx, "Failed to marshal JSON for WriteJSON", "error", err.Error())
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ctxToWrite := c.connCtx
	var cancel context.CancelFunc
	if c.writeTimeoutSeconds > 0 {
		ctxToWrite, cancel = context.WithTimeout(c.connCtx, time.Duration(c.writeTimeoutSeconds)*time.Second)
		defer cancel()
	}
	return c.wsConn.Write(ctxToWrite, websocket.MessageText, payload)
}
func (c *Connection) ReadMessage(ctx context.Context) (websocket.MessageType, []byte, error) {
	return c.wsConn.Read(ctx)
}
func (c *Connection) RemoteAddr() string {
	return c.remoteAddrStr
}
func (c *Connection) UnderlyingConn() *websocket.Conn {
	return c.wsConn
}
func (c *Connection) LastPongTime() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPongTime
}
func (c *Connection) UpdateLastPongTime() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastPongTime = time.Now()
}
func (c *Connection) Ping(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctxToWrite := c.connCtx
	var cancel context.CancelFunc
	if c.writeTimeoutSeconds > 0 {
		ctxToWrite, cancel = context.WithTimeout(c.connCtx, time.Duration(c.writeTimeoutSeconds)*time.Second)
		defer cancel()
	}
	return c.wsConn.Ping(ctxToWrite)
}
```

## File: internal/adapters/websocket/protocol.go
```go
package websocket
import (
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
const (
	MessageTypeReady      = "ready"
	MessageTypeEvent      = "event"
	MessageTypeError      = "error"
	MessageTypeSelectChat = "select_chat"
)
type BaseMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
}
type SelectChatMessagePayload struct {
	ChatID string `json:"chat_id"`
}
func NewReadyMessage() BaseMessage {
	return BaseMessage{
		Type: MessageTypeReady,
	}
}
func NewEventMessage(eventData interface{}) BaseMessage {
	return BaseMessage{
		Type:    MessageTypeEvent,
		Payload: eventData,
	}
}
func NewErrorMessage(errResp domain.ErrorResponse) BaseMessage {
	return BaseMessage{
		Type:    MessageTypeError,
		Payload: errResp,
	}
}
```

## File: internal/domain/logger.go
```go
package domain
import (
	"context"
)
type Logger interface {
	Debug(ctx context.Context, msg string, fields ...any)
	Info(ctx context.Context, msg string, fields ...any)
	Warn(ctx context.Context, msg string, fields ...any)
	Error(ctx context.Context, msg string, fields ...any)
	Fatal(ctx context.Context, msg string, fields ...any)
	With(fields ...any) Logger
}
```

## File: internal/domain/nats_payloads.go
```go
package domain
import "time"
type EnrichedEventPayload struct {
	EventID   string      `json:"event_id"`
	EventType string      `json:"event_type"`
	Timestamp time.Time   `json:"timestamp"`
	Source    string      `json:"source"`
	Data      interface{} `json:"data"`
}
```

## File: internal/domain/session.go
```go
package domain
import (
	"context"
	"time"
)
type SessionLockManager interface {
	AcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)
	ReleaseLock(ctx context.Context, key string, value string) (bool, error)
	RefreshLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)
	ForceAcquireLock(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)
}
type KillSwitchMessage struct {
	NewPodID string `json:"new_pod_id"`
}
type KillSwitchPublisher interface {
	PublishSessionKill(ctx context.Context, channel string, message KillSwitchMessage) error
}
type KillSwitchMessageHandler func(channel string, message KillSwitchMessage) error
type KillSwitchSubscriber interface {
	SubscribeToSessionKillPattern(ctx context.Context, pattern string, handler KillSwitchMessageHandler) error
	Close() error
}
```

## File: internal/domain/websocket.go
```go
package domain
import (
	"context"
	"github.com/coder/websocket"
)
type ManagedConnection interface {
	Close(statusCode websocket.StatusCode, reason string) error
	WriteJSON(v interface{}) error
	RemoteAddr() string
	Context() context.Context
}
```

## File: pkg/crypto/hash.go
```go
package crypto
import (
	"crypto/sha256"
	"encoding/hex"
)
func Sha256Hex(input string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}
```

## File: pkg/safego/safego.go
```go
package safego
import (
	"context"
	"fmt"
	"runtime/debug"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
func Execute(ctx context.Context, logger domain.Logger, goroutineName string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logCtx := ctx
				if ctx.Err() != nil {
					logCtx = context.Background()
				}
				logger.Error(logCtx, fmt.Sprintf("Panic recovered in goroutine: %s", goroutineName),
					"panic_info", fmt.Sprintf("%v", r),
					"stacktrace", string(debug.Stack()),
				)
			}
		}()
		fn()
	}()
}
```

## File: .gitignore
```
# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
dev-debug.log

# Dependency directories
node_modules/

# Environment variables
.env

# Editor directories and files
.idea
.vscode
*.suo
*.ntvs*
*.njsproj
*.sln
*.sw?

# OS specific
.DS_Store

# Task files
tasks.json
tasks/
```

## File: Dockerfile
```dockerfile
# Builder Stage
ARG GO_VERSION=1.23
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /app

# Set CGO_ENABLED=0 for static builds
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the rest of the application source code
COPY . .

# Build the application
# Output binary to /app/daisi-ws-service
RUN go build -v -o /app/daisi-ws-service ./cmd/daisi-ws-service

# ---

# Final Stage
FROM debian:bookworm-slim

WORKDIR /app

# Create a non-root user and group
RUN groupadd --system appuser && useradd --system --gid appuser appuser

# Copy the compiled binary from the builder stage
COPY --from=builder /app/daisi-ws-service /app/daisi-ws-service

# Copy configuration (assuming it will be in /app/config)
# We might need to adjust this later if config path changes or is mounted differently
COPY config /app/config 
# Ensure the config directory and file have correct permissions if they exist
# RUN if [ -d /app/config ]; then chown -R appuser:appuser /app/config && chmod -R u+rX,g+rX /app/config; fi

# Set permissions for the binary
RUN chown appuser:appuser /app/daisi-ws-service && chmod u+x /app/daisi-ws-service

# Switch to the non-root user
USER appuser

# Expose the default port the application will listen on (adjust if necessary)
# Placeholder, will be defined by HTTP/gRPC server implementation later
# EXPOSE 8080 
# EXPOSE 50051

# Set the entrypoint
ENTRYPOINT ["/app/daisi-ws-service"]
```

## File: cmd/daisi-ws-service/main.go
```go
package main
import (
	"context"
	"fmt"
	"os"
	"gitlab.com/timkado/api/daisi-ws-service/internal/bootstrap"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
)
func main() {
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.RequestIDKey, "app-main")
	app, cleanup, err := bootstrap.InitializeApp(ctx)
	if err != nil {
		fmt.Printf("Failed to initialize application: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	if err := app.Run(ctx); err != nil {
		fmt.Printf("Application run failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Application exited gracefully.")
}
```

## File: internal/adapters/middleware/admin_auth.go
```go
package middleware
import (
	"context"
	"errors"
	"net/http"
	"strings"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
)
func TokenGenerationAuthMiddleware(cfgProvider config.Provider, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminApiKey := r.Header.Get(apiKeyHeaderName)
			cfg := cfgProvider.Get()
			if cfg == nil || cfg.Auth.TokenGenerationAdminKey == "" {
				logger.Error(r.Context(), "Token generation auth failed: TokenGenerationAdminKey not configured", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Token generation auth cannot be performed.")
				errResp.WriteJSON(w, http.StatusInternalServerError)
				return
			}
			if adminApiKey == "" {
				logger.Warn(r.Context(), "Token generation auth failed: Admin key missing", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrUnauthorized, "Admin API key is required", "Provide admin API key in X-API-Key header.")
				errResp.WriteJSON(w, http.StatusUnauthorized)
				return
			}
			if adminApiKey != cfg.Auth.TokenGenerationAdminKey {
				logger.Warn(r.Context(), "Token generation auth failed: Invalid admin key", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrForbidden, "Invalid admin API key", "The provided admin API key is not valid.")
				errResp.WriteJSON(w, http.StatusForbidden)
				return
			}
			logger.Debug(r.Context(), "Token generation admin key authentication successful", "path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}
const (
	adminTokenQueryParam = "token"
)
func AdminAuthMiddleware(authService *application.AuthService, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenValue := r.URL.Query().Get(adminTokenQueryParam)
			if tokenValue == "" {
				logger.Warn(r.Context(), "Admin token authentication failed: 'token' query parameter missing", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInvalidToken, "Admin token is required", "Provide 'token' in query parameter.")
				errResp.WriteJSON(w, http.StatusForbidden)
				return
			}
			adminCtx, err := authService.ProcessAdminToken(r.Context(), tokenValue)
			if err != nil {
				logger.Warn(r.Context(), "Admin token processing failed", "path", r.URL.Path, "error", err.Error())
				var errCode domain.ErrorCode
				var errMsg string
				var errDetails string = err.Error()
				httpStatus := http.StatusForbidden
				switch {
				case errors.Is(err, application.ErrTokenExpired):
					errCode = domain.ErrInvalidToken
					errMsg = "Admin token has expired."
				case errors.Is(err, crypto.ErrTokenDecryptionFailed),
					errors.Is(err, application.ErrTokenPayloadInvalid),
					errors.Is(err, crypto.ErrInvalidTokenFormat),
					errors.Is(err, crypto.ErrCiphertextTooShort):
					errCode = domain.ErrInvalidToken
					errMsg = "Admin token is invalid or malformed."
					errDetails = "Token format or content error."
				case errors.Is(err, crypto.ErrInvalidAESKeySize),
					strings.Contains(err.Error(), "application not configured for admin token decryption"):
					errCode = domain.ErrInternal
					errMsg = "Server configuration error processing admin token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
				default:
					logger.Error(r.Context(), "Unexpected internal error during admin token processing", "path", r.URL.Path, "detailed_error", err.Error())
					errCode = domain.ErrInternal
					errMsg = "An unexpected error occurred while processing admin token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
				}
				domain.NewErrorResponse(errCode, errMsg, errDetails).WriteJSON(w, httpStatus)
				return
			}
			newReqCtx := context.WithValue(r.Context(), contextkeys.AdminUserContextKey, adminCtx)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.UserIDKey, adminCtx.AdminID)
			logger.Debug(r.Context(), "Admin token authentication successful",
				"path", r.URL.Path,
				"admin_id", adminCtx.AdminID,
				"company_restriction", adminCtx.CompanyIDRestriction)
			next.ServeHTTP(w, r.WithContext(newReqCtx))
		})
	}
}
```

## File: internal/adapters/middleware/auth.go
```go
package middleware
import (
	"context"
	"errors"
	"net/http"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
)
const (
	apiKeyHeaderName = "X-API-Key"
	apiKeyQueryParam = "x-api-key"
	tokenQueryParam  = "token"
)
func APIKeyAuthMiddleware(cfgProvider config.Provider, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get(apiKeyHeaderName)
			if apiKey == "" {
				apiKey = r.URL.Query().Get(apiKeyQueryParam)
			}
			cfg := cfgProvider.Get()
			if cfg == nil || cfg.Auth.SecretToken == "" {
				logger.Error(r.Context(), "API key authentication failed: SecretToken not configured", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "API authentication cannot be performed.")
				errResp.WriteJSON(w, http.StatusInternalServerError)
				return
			}
			if apiKey == "" {
				logger.Warn(r.Context(), "API key authentication failed: Key missing", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInvalidAPIKey, "API key is required", "Provide API key in X-API-Key header or x-api-key query parameter.")
				errResp.WriteJSON(w, http.StatusUnauthorized)
				return
			}
			if apiKey != cfg.Auth.SecretToken {
				logger.Warn(r.Context(), "API key authentication failed: Invalid key", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInvalidAPIKey, "Invalid API key", "The provided API key is not valid.")
				errResp.WriteJSON(w, http.StatusUnauthorized)
				return
			}
			logger.Debug(r.Context(), "API key authentication successful", "path", r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}
func CompanyTokenAuthMiddleware(authService *application.AuthService, logger domain.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenValue := r.URL.Query().Get(tokenQueryParam)
			if tokenValue == "" {
				logger.Warn(r.Context(), "Company token authentication failed: 'token' query parameter missing", "path", r.URL.Path)
				errResp := domain.NewErrorResponse(domain.ErrInvalidToken, "Company token is required", "Provide 'token' in query parameter.")
				errResp.WriteJSON(w, http.StatusForbidden)
				return
			}
			authCtx, err := authService.ProcessToken(r.Context(), tokenValue)
			if err != nil {
				logger.Warn(r.Context(), "Company token processing failed", "path", r.URL.Path, "error", err.Error())
				var errCode domain.ErrorCode
				var errMsg string
				var errDetails string = err.Error()
				httpStatus := http.StatusForbidden
				switch {
				case errors.Is(err, application.ErrTokenExpired):
					errCode = domain.ErrInvalidToken
					errMsg = "Company token has expired."
				case errors.Is(err, crypto.ErrTokenDecryptionFailed),
					errors.Is(err, application.ErrTokenPayloadInvalid),
					errors.Is(err, crypto.ErrInvalidTokenFormat),
					errors.Is(err, crypto.ErrCiphertextTooShort):
					errCode = domain.ErrInvalidToken
					errMsg = "Company token is invalid or malformed."
					errDetails = "Token format or content error."
				case errors.Is(err, crypto.ErrInvalidAESKeySize),
					errors.New("application not configured for token decryption").Error() == err.Error():
					errCode = domain.ErrInternal
					errMsg = "Server configuration error processing token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
				default:
					logger.Error(r.Context(), "Unexpected internal error during token processing", "path", r.URL.Path, "detailed_error", err.Error())
					errCode = domain.ErrInternal
					errMsg = "An unexpected error occurred."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
				}
				errResp := domain.NewErrorResponse(errCode, errMsg, errDetails)
				errResp.WriteJSON(w, httpStatus)
				return
			}
			newReqCtx := context.WithValue(r.Context(), contextkeys.AuthUserContextKey, authCtx)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.CompanyIDKey, authCtx.CompanyID)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.AgentIDKey, authCtx.AgentID)
			newReqCtx = context.WithValue(newReqCtx, contextkeys.UserIDKey, authCtx.UserID)
			logger.Debug(r.Context(), "Company token authentication successful",
				"path", r.URL.Path,
				"company_id", authCtx.CompanyID,
				"user_id", authCtx.UserID)
			next.ServeHTTP(w, r.WithContext(newReqCtx))
		})
	}
}
```

## File: internal/adapters/nats/consumer.go
```go
package nats
import (
	"context"
	"fmt"
	"time"
	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
type ConsumerAdapter struct {
	nc                *nats.Conn
	js                nats.JetStreamContext
	logger            domain.Logger
	cfg               *config.NATSConfig
	appName           string
	natsMaxAckPending int
}
func NewConsumerAdapter(ctx context.Context, cfgProvider config.Provider, appLogger domain.Logger) (*ConsumerAdapter, func(), error) {
	appFullCfg := cfgProvider.Get()
	natsCfg := appFullCfg.NATS
	appName := appFullCfg.App.ServiceName
	natsMaxAckPending := appFullCfg.App.NATSMaxAckPending
	appLogger.Info(ctx, "Attempting to connect to NATS server", "url", natsCfg.URL)
	nc, err := nats.Connect(natsCfg.URL,
		nats.Name(fmt.Sprintf("%s-consumer-%s", appName, appFullCfg.Server.PodID)),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(5),
		nats.ReconnectWait(2*time.Second),
		nats.Timeout(5*time.Second),
		nats.ErrorHandler(func(c *nats.Conn, s *nats.Subscription, err error) {
			appLogger.Error(ctx, "NATS error", "subscription", s.Subject, "error", err.Error())
		}),
		nats.ClosedHandler(func(c *nats.Conn) {
			appLogger.Info(ctx, "NATS connection closed")
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			appLogger.Info(ctx, "NATS reconnected", "url", c.ConnectedUrl())
		}),
		nats.DisconnectErrHandler(func(c *nats.Conn, err error) {
			appLogger.Warn(ctx, "NATS disconnected", "error", err)
		}),
	)
	if err != nil {
		appLogger.Error(ctx, "Failed to connect to NATS", "url", natsCfg.URL, "error", err.Error())
		return nil, nil, fmt.Errorf("failed to connect to NATS at %s: %w", natsCfg.URL, err)
	}
	appLogger.Info(ctx, "Successfully connected to NATS server", "url", nc.ConnectedUrl())
	js, err := nc.JetStream(nats.PublishAsyncMaxPending(256))
	if err != nil {
		appLogger.Error(ctx, "Failed to get JetStream context", "error", err.Error())
		nc.Close()
		return nil, nil, fmt.Errorf("failed to get JetStream context: %w", err)
	}
	appLogger.Info(ctx, "Successfully obtained JetStream context")
	adapter := &ConsumerAdapter{
		nc:                nc,
		js:                js,
		logger:            appLogger,
		cfg:               &natsCfg,
		appName:           appName,
		natsMaxAckPending: natsMaxAckPending,
	}
	cleanup := func() {
		appLogger.Info(context.Background(), "Closing NATS connection...")
		adapter.Close()
	}
	return adapter, cleanup, nil
}
func (a *ConsumerAdapter) Close() {
	if a.nc != nil && !a.nc.IsClosed() {
		a.logger.Info(context.Background(), "Draining NATS connection...")
		if err := a.nc.Drain(); err != nil {
			a.logger.Error(context.Background(), "Error draining NATS connection", "error", err.Error())
		} else {
			a.logger.Info(context.Background(), "NATS connection drained successfully.")
		}
	}
}
func (a *ConsumerAdapter) JetStreamContext() nats.JetStreamContext {
	return a.js
}
func (a *ConsumerAdapter) NatsConn() *nats.Conn {
	return a.nc
}
func (a *ConsumerAdapter) SubscribeToChats(ctx context.Context, companyID, agentID string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}
	subject := fmt.Sprintf("wa.%s.%s.chats", companyID, agentID)
	queueGroup := "ws_fanout"
	a.logger.Info(ctx, "Attempting to subscribe to NATS subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"stream_name", a.cfg.StreamName,
		"consumer_name", a.cfg.ConsumerName,
	)
	durableName := a.cfg.ConsumerName
	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		handler,
		nats.Durable(durableName),
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckWait(30*time.Second),
		nats.MaxAckPending(a.natsMaxAckPending),
	)
	if err != nil {
		a.logger.Error(ctx, "Failed to subscribe to NATS subject",
			"subject", subject,
			"queue_group", queueGroup,
			"durable_name", durableName,
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to subscribe to NATS subject %s: %w", subject, err)
	}
	a.logger.Info(ctx, "Successfully subscribed to NATS subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"durable_name", durableName,
	)
	return sub, nil
}
func (a *ConsumerAdapter) SubscribeToAgentEvents(ctx context.Context, companyIDPattern, agentIDPattern string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}
	subject := fmt.Sprintf("wa.%s.%s.agents", companyIDPattern, agentIDPattern)
	queueGroup := "ws_fanout_admin"
	queueGroup = "ws_fanout"
	a.logger.Info(ctx, "Attempting to subscribe to NATS agent events subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"stream_name", a.cfg.StreamName,
		"consumer_name", a.cfg.ConsumerName,
	)
	durableName := a.cfg.ConsumerName
	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		handler,
		nats.Durable(durableName+"_admin_agents"),
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckWait(30*time.Second),
		nats.MaxAckPending(a.natsMaxAckPending),
	)
	if err != nil {
		a.logger.Error(ctx, "Failed to subscribe to NATS agent events subject",
			"subject", subject,
			"queue_group", queueGroup,
			"durable_name", durableName+"_admin_agents",
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to subscribe to NATS agent events subject %s: %w", subject, err)
	}
	a.logger.Info(ctx, "Successfully subscribed to NATS agent events subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"durable_name", durableName+"_admin_agents",
	)
	return sub, nil
}
```

## File: internal/adapters/redis/kill_switch_pubsub.go
```go
package redis
import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)
type KillSwitchPubSubAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
	sub         *redis.PubSub
}
func NewKillSwitchPubSubAdapter(redisClient *redis.Client, logger domain.Logger) *KillSwitchPubSubAdapter {
	return &KillSwitchPubSubAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}
func (a *KillSwitchPubSubAdapter) PublishSessionKill(ctx context.Context, channel string, message domain.KillSwitchMessage) error {
	payloadBytes, err := json.Marshal(message)
	if err != nil {
		a.logger.Error(ctx, "Failed to marshal KillSwitchMessage for publishing", "channel", channel, "error", err.Error())
		return fmt.Errorf("failed to marshal KillSwitchMessage: %w", err)
	}
	err = a.redisClient.Publish(ctx, channel, string(payloadBytes)).Err()
	if err != nil {
		a.logger.Error(ctx, "Failed to publish session kill message to Redis", "channel", channel, "error", err.Error())
		return fmt.Errorf("failed to publish to Redis channel '%s': %w", channel, err)
	}
	a.logger.Info(ctx, "Successfully published session kill message", "channel", channel, "new_pod_id", message.NewPodID)
	return nil
}
func (a *KillSwitchPubSubAdapter) SubscribeToSessionKillPattern(ctx context.Context, pattern string, handler domain.KillSwitchMessageHandler) error {
	if a.sub != nil {
		return fmt.Errorf("already subscribed or subscription active on this adapter instance")
	}
	a.sub = a.redisClient.PSubscribe(ctx, pattern)
	if _, err := a.sub.Receive(ctx); err != nil {
		a.logger.Error(ctx, "Failed to confirm Redis PSubscribe", "pattern", pattern, "error", err.Error())
		_ = a.sub.Close()
		a.sub = nil
		return fmt.Errorf("failed to subscribe to pattern '%s': %w", pattern, err)
	}
	a.logger.Info(ctx, "Successfully subscribed to Redis pattern", "pattern", pattern)
	ch := a.sub.Channel()
	safego.Execute(ctx, a.logger, fmt.Sprintf("RedisKillSwitchMessageProcessor-%s", pattern), func() {
		for {
			select {
			case msg, ok := <-ch:
				if !ok {
					a.logger.Info(ctx, "Redis pub/sub channel closed for pattern", "pattern", pattern)
					return
				}
				var killMsg domain.KillSwitchMessage
				if errUnmarshal := json.Unmarshal([]byte(msg.Payload), &killMsg); errUnmarshal != nil {
					a.logger.Error(ctx, "Failed to unmarshal KillSwitchMessage from pub/sub",
						"channel", msg.Channel,
						"payload", msg.Payload,
						"error", errUnmarshal.Error(),
					)
					continue
				}
				a.logger.Info(ctx, "Received session kill message", "channel", msg.Channel, "new_pod_id", killMsg.NewPodID)
				if errHandler := handler(msg.Channel, killMsg); errHandler != nil {
					a.logger.Error(ctx, "Error in KillSwitchMessageHandler",
						"channel", msg.Channel,
						"new_pod_id", killMsg.NewPodID,
						"error", errHandler.Error(),
					)
				}
			case <-ctx.Done():
				a.logger.Info(ctx, "Context cancelled, stopping Redis message processor for pattern", "pattern", pattern)
				return
			}
		}
	})
	return nil
}
func (a *KillSwitchPubSubAdapter) Close() error {
	if a.sub != nil {
		err := a.sub.Close()
		a.sub = nil
		if err != nil {
			a.logger.Error(context.Background(), "Error closing Redis pub/sub subscription", "error", err.Error())
			return fmt.Errorf("error closing Redis pub/sub: %w", err)
		}
		a.logger.Info(context.Background(), "Redis pub/sub subscription closed.")
		return nil
	}
	return fmt.Errorf("no active subscription to close")
}
```

## File: internal/adapters/websocket/admin_handler.go
```go
package websocket
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)
type AdminHandler struct {
	logger         domain.Logger
	configProvider config.Provider
	connManager    *application.ConnectionManager
	natsAdapter    *appnats.ConsumerAdapter
}
func NewAdminHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter *appnats.ConsumerAdapter) *AdminHandler {
	return &AdminHandler{
		logger:         logger,
		configProvider: cfgProvider,
		connManager:    connManager,
		natsAdapter:    natsAdapter,
	}
}
func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	adminCtx, ok := r.Context().Value(contextkeys.AdminUserContextKey).(*domain.AdminUserContext)
	if !ok || adminCtx == nil {
		h.logger.Error(r.Context(), "AdminUserContext not found after middleware chain for /ws/admin")
		domain.NewErrorResponse(domain.ErrInternal, "Authentication context missing", "Server configuration error.").WriteJSON(w, http.StatusInternalServerError)
		return
	}
	h.logger.Info(r.Context(), "/ws/admin endpoint hit by admin", "admin_id", adminCtx.AdminID)
	adminSessionKey := rediskeys.AdminSessionKey(adminCtx.AdminID)
	currentPodID := h.configProvider.Get().Server.PodID
	lockAcqCtx, lockAcqCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer lockAcqCancel()
	acquired, err := h.connManager.AcquireAdminSessionLockOrNotify(lockAcqCtx, adminCtx.AdminID)
	if err != nil {
		h.logger.Error(r.Context(), "Failed during admin session lock acquisition attempt via ConnectionManager", "error", err, "admin_id", adminCtx.AdminID)
		domain.NewErrorResponse(domain.ErrInternal, "Failed to process admin session.", err.Error()).WriteJSON(w, http.StatusInternalServerError)
		return
	}
	if !acquired {
		h.logger.Warn(r.Context(), "Admin session lock not acquired (conflict)", "admin_id", adminCtx.AdminID)
		domain.NewErrorResponse(domain.ErrSessionConflict, "Admin session already active elsewhere.", "").WriteJSON(w, http.StatusConflict)
		return
	}
	h.logger.Info(r.Context(), "Admin session lock successfully acquired", "admin_session_key", adminSessionKey)
	wsConnLifetimeCtx, cancelWsConnLifetimeCtx := context.WithCancel(r.Context())
	var wrappedConn *Connection
	opts := websocket.AcceptOptions{
		Subprotocols: []string{"json.v1"},
		OnPongReceived: func(ctx context.Context, pongPayload []byte) {
			if wrappedConn != nil {
				h.logger.Debug(wrappedConn.Context(), "Admin Pong received")
				wrappedConn.UpdateLastPongTime()
			}
		},
	}
	c, err := websocket.Accept(w, r, &opts)
	if err != nil {
		h.logger.Error(r.Context(), "Admin WebSocket upgrade failed", "error", err, "admin_id", adminCtx.AdminID)
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer releaseCancel()
			// This should use the actual podID that acquired the lock
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, adminSessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(r.Context(), "Failed to release admin session lock after upgrade failure", "sessionKey", adminSessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(r.Context(), "Successfully released admin session lock after upgrade failure", "sessionKey", adminSessionKey)
			}
		}
		cancelWsConnLifetimeCtx()
		return
	}
	wrappedConn = NewConnection(wsConnLifetimeCtx, cancelWsConnLifetimeCtx, c, r.RemoteAddr, h.logger, h.configProvider)
	h.logger.Info(wrappedConn.Context(), "Admin WebSocket connection established",
		"remoteAddr", wrappedConn.RemoteAddr(),
		"subprotocol", c.Subprotocol(),
		"admin_id", adminCtx.AdminID,
		"admin_session_key", adminSessionKey,
	)
	h.connManager.RegisterConnection(adminSessionKey, wrappedConn)
	defer func() {
		h.logger.Info(wrappedConn.Context(), "Admin connection management goroutine finished. Deregistering admin connection.", "admin_session_key", adminSessionKey)
		h.connManager.DeregisterConnection(adminSessionKey)
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer releaseCancel()
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, adminSessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(wrappedConn.Context(), "Failed to release admin session lock on connection close", "admin_session_key", adminSessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(wrappedConn.Context(), "Successfully released admin session lock on connection close", "admin_session_key", adminSessionKey)
			} else {
				h.logger.Warn(wrappedConn.Context(), "Failed to release admin session lock on connection close (not held or value mismatch)", "admin_session_key", adminSessionKey)
			}
		}
	}()
	safego.Execute(wsConnLifetimeCtx, h.logger, fmt.Sprintf("AdminWebSocketConnectionManager-%s", adminSessionKey), func() {
		h.manageAdminConnection(wsConnLifetimeCtx, wrappedConn, adminCtx)
	})
}
func (h *AdminHandler) manageAdminConnection(connCtx context.Context, conn *Connection, adminInfo *domain.AdminUserContext) {
	defer conn.Close(websocket.StatusNormalClosure, "admin connection ended")
	h.logger.Info(connCtx, "Admin WebSocket connection management started",
		"admin_id", adminInfo.AdminID,
		"remote_addr", conn.RemoteAddr(),
	)
	readyMessage := NewReadyMessage()
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to admin client", "error", err.Error(), "admin_id", adminInfo.AdminID)
		return
	}
	h.logger.Info(connCtx, "Sent 'ready' message to admin client", "admin_id", adminInfo.AdminID)
	var natsSubscription *nats.Subscription
	if h.natsAdapter != nil {
		companyPattern := adminInfo.SubscribedCompanyID
		agentPattern := adminInfo.SubscribedAgentID
		if companyPattern == "" {
			companyPattern = "*"
		} // Default to wildcard if not specified
		if agentPattern == "" {
			agentPattern = "*"
		} // Default to wildcard if not specified
		natsMsgHandler := func(msg *nats.Msg) {
			h.logger.Info(connCtx, "Admin NATS: Received message on agent events subject",
				"subject", msg.Subject, "data_len", len(msg.Data), "admin_id", adminInfo.AdminID,
			)
			var eventPayload domain.EnrichedEventPayload
			if err := json.Unmarshal(msg.Data, &eventPayload); err != nil {
				h.logger.Error(connCtx, "Admin NATS: Failed to unmarshal agent event payload", "subject", msg.Subject, "error", err.Error(), "admin_id", adminInfo.AdminID)
				_ = msg.Ack()
				return
			}
			wsMessage := NewEventMessage(eventPayload)
			if err := conn.WriteJSON(wsMessage); err != nil {
				h.logger.Error(connCtx, "Admin NATS: Failed to forward agent event to WebSocket", "subject", msg.Subject, "error", err.Error(), "admin_id", adminInfo.AdminID)
			}
			_ = msg.Ack()
		}
		var subErr error
		natsSubscription, subErr = h.natsAdapter.SubscribeToAgentEvents(connCtx, companyPattern, agentPattern, natsMsgHandler)
		if subErr != nil {
			h.logger.Error(connCtx, "Failed to subscribe to NATS agent events for admin",
				"companyPattern", companyPattern, "agentPattern", agentPattern, "error", subErr.Error(), "admin_id", adminInfo.AdminID,
			)
			errorMsg := domain.NewErrorResponse(domain.ErrSubscriptionFailure, "Could not subscribe to agent events", subErr.Error())
			conn.WriteJSON(NewErrorMessage(errorMsg))
		} else {
			h.logger.Info(connCtx, "Successfully subscribed to NATS agent events for admin",
				"companyPattern", companyPattern, "agentPattern", agentPattern, "subject", natsSubscription.Subject, "admin_id", adminInfo.AdminID,
			)
			defer func() {
				if natsSubscription != nil {
					h.logger.Info(connCtx, "Unsubscribing from NATS agent events for admin", "subject", natsSubscription.Subject, "admin_id", adminInfo.AdminID)
					if unsubErr := natsSubscription.Drain(); unsubErr != nil {
						h.logger.Error(connCtx, "Error draining NATS admin subscription", "subject", natsSubscription.Subject, "error", unsubErr.Error())
					}
				}
			}()
		}
	} else {
		h.logger.Warn(connCtx, "NATS adapter not available for admin handler, cannot subscribe to agent events.", "admin_id", adminInfo.AdminID)
	}
	appCfg := conn.config
	pingInterval := time.Duration(appCfg.PingIntervalSeconds) * time.Second
	pongWaitDuration := time.Duration(appCfg.PongWaitSeconds) * time.Second
	writeTimeout := time.Duration(appCfg.WriteTimeoutSeconds) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}
	if pingInterval > 0 {
		pinger := time.NewTicker(pingInterval)
		defer pinger.Stop()
		safego.Execute(connCtx, conn.logger, fmt.Sprintf("AdminWebSocketPinger-%s", conn.RemoteAddr()), func() {
			for {
				select {
				case <-pinger.C:
					pingWriteCtx, pingCancel := context.WithTimeout(connCtx, writeTimeout)
					if err := conn.Ping(pingWriteCtx); err != nil {
						h.logger.Error(connCtx, "Failed to send ping to admin client", "error", err.Error(), "admin_id", adminInfo.AdminID)
						pingCancel()
						conn.Close(websocket.StatusAbnormalClosure, "Admin Ping failure")
						return
					}
					pingCancel()
					h.logger.Debug(connCtx, "Sent ping to admin client", "admin_id", adminInfo.AdminID)
					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Admin Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr(), "admin_id", adminInfo.AdminID)
						conn.Close(websocket.StatusPolicyViolation, "Admin Pong timeout")
						return
					}
				case <-connCtx.Done():
					h.logger.Info(connCtx, "Admin connection context done in pinger, stopping pinger.", "admin_id", adminInfo.AdminID)
					return
				}
			}
		})
	}
	for {
		var readCtx context.Context
		var cancelRead context.CancelFunc
		if pongWaitDuration > 0 {
			readCtx, cancelRead = context.WithTimeout(connCtx, pongWaitDuration)
		} else {
			readCtx = connCtx
		}
		msgType, p, errRead := conn.ReadMessage(readCtx)
		if cancelRead != nil {
			cancelRead()
		}
		if errRead != nil {
			if errors.Is(readCtx.Err(), context.DeadlineExceeded) {
				h.logger.Warn(connCtx, "Admin Pong timeout: No message received. Closing connection.", "admin_id", adminInfo.AdminID)
				conn.Close(websocket.StatusPolicyViolation, "Admin Pong timeout")
				return
			}
			closeStatus := websocket.CloseStatus(errRead)
			if closeStatus == websocket.StatusNormalClosure || closeStatus == websocket.StatusGoingAway {
				h.logger.Info(connCtx, "Admin WebSocket connection closed by peer", "status_code", closeStatus, "admin_id", adminInfo.AdminID)
			} else if errors.Is(errRead, context.Canceled) || connCtx.Err() == context.Canceled {
				h.logger.Info(connCtx, "Admin WebSocket connection context canceled.", "admin_id", adminInfo.AdminID)
			} else if closeStatus == -1 && (strings.Contains(strings.ToLower(errRead.Error()), "eof") || strings.Contains(strings.ToLower(errRead.Error()), "closed")) {
				h.logger.Info(connCtx, "Admin WebSocket read EOF or closed. Peer disconnected.", "admin_id", adminInfo.AdminID, "error", errRead.Error())
			} else {
				h.logger.Error(connCtx, "Error reading from admin WebSocket", "error", errRead.Error(), "admin_id", adminInfo.AdminID)
			}
			return
		}
		h.logger.Debug(connCtx, "Received message from admin WebSocket", "type", msgType.String(), "payload_len", len(p), "admin_id", adminInfo.AdminID)
	}
}
```

## File: internal/application/auth_service.go
```go
package application
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)
var (
	ErrTokenPayloadInvalid = errors.New("token payload is invalid")
	ErrTokenExpired        = errors.New("token has expired")
	ErrCacheMiss           = errors.New("token not found in cache")
)
type AuthService struct {
	logger     domain.Logger
	config     config.Provider
	cache      domain.TokenCacheStore
	adminCache domain.AdminTokenCacheStore
}
func NewAuthService(logger domain.Logger, config config.Provider, cache domain.TokenCacheStore, adminCache domain.AdminTokenCacheStore) *AuthService {
	if logger == nil {
		panic("logger is nil in NewAuthService")
	}
	if config == nil {
		panic("config provider is nil in NewAuthService")
	}
	if cache == nil {
		logger.Warn(context.Background(), "Company token cache (TokenCacheStore) is nil in NewAuthService. Company token caching will be disabled.")
	}
	if adminCache == nil {
		panic("admin token cache store is nil in NewAuthService")
	}
	return &AuthService{
		logger:     logger,
		config:     config,
		cache:      cache,
		adminCache: adminCache,
	}
}
func (s *AuthService) ParseAndValidateDecryptedToken(decryptedPayload []byte, rawTokenB64 string) (*domain.AuthenticatedUserContext, error) {
	var ctx domain.AuthenticatedUserContext
	err := json.Unmarshal(decryptedPayload, &ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal token JSON: %v", ErrTokenPayloadInvalid, err)
	}
	if ctx.CompanyID == "" || ctx.AgentID == "" || ctx.UserID == "" || ctx.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: missing essential fields (company_id, agent_id, user_id, expires_at)", ErrTokenPayloadInvalid)
	}
	if time.Now().After(ctx.ExpiresAt) {
		return nil, fmt.Errorf("%w: token expired at %v", ErrTokenExpired, ctx.ExpiresAt)
	}
	ctx.Token = rawTokenB64
	return &ctx, nil
}
func (s *AuthService) ParseAndValidateAdminDecryptedToken(decryptedPayload []byte, rawTokenB64 string) (*domain.AdminUserContext, error) {
	var adminCtx domain.AdminUserContext
	err := json.Unmarshal(decryptedPayload, &adminCtx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal admin token JSON: %v", ErrTokenPayloadInvalid, err)
	}
	if adminCtx.AdminID == "" || adminCtx.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: missing essential fields (admin_id, expires_at) in admin token", ErrTokenPayloadInvalid)
	}
	if time.Now().After(adminCtx.ExpiresAt) {
		return nil, fmt.Errorf("%w: admin token expired at %v", ErrTokenExpired, adminCtx.ExpiresAt)
	}
	adminCtx.Token = rawTokenB64
	return &adminCtx, nil
}
func (s *AuthService) ProcessToken(reqCtx context.Context, tokenB64 string) (*domain.AuthenticatedUserContext, error) {
	cacheKey := rediskeys.TokenCacheKey(tokenB64)
	cachedCtx, err := s.cache.Get(reqCtx, cacheKey)
	if err == nil && cachedCtx != nil {
		if time.Now().After(cachedCtx.ExpiresAt) {
			s.logger.Warn(reqCtx, "Cached token found but was expired", "cache_key", cacheKey, "expires_at", cachedCtx.ExpiresAt)
		} else {
			s.logger.Debug(reqCtx, "Token found in cache and is valid", "cache_key", cacheKey)
			return cachedCtx, nil
		}
	} else if err != nil && !errors.Is(err, ErrCacheMiss) {
		s.logger.Error(reqCtx, "Error retrieving token from cache", "cache_key", cacheKey, "error", err.Error())
	}
	s.logger.Debug(reqCtx, "Token not found in cache or cache error, proceeding to decrypt", "cache_key", cacheKey)
	aesKeyHex := s.config.Get().Auth.TokenAESKey
	if aesKeyHex == "" {
		s.logger.Error(reqCtx, "TOKEN_AES_KEY not configured", "config_key", "auth.token_aes_key")
		return nil, errors.New("application not configured for token decryption")
	}
	decryptedPayload, err := crypto.DecryptAESGCM(aesKeyHex, tokenB64)
	if err != nil {
		s.logger.Warn(reqCtx, "Token decryption failed", "error", err.Error())
		return nil, err
	}
	validatedCtx, err := s.ParseAndValidateDecryptedToken(decryptedPayload, tokenB64)
	if err != nil {
		s.logger.Warn(reqCtx, "Decrypted token failed validation", "error", err.Error())
		return nil, err
	}
	cacheTTLSeconds := s.config.Get().Auth.TokenCacheTTLSeconds
	cacheTTL := time.Duration(cacheTTLSeconds) * time.Second
	if cacheTTLSeconds == 0 {
		cacheTTL = 30 * time.Second
		s.logger.Debug(reqCtx, "auth.tokenCacheTTLSeconds not configured or zero, using default 30s", "cache_key", cacheKey)
	}
	if err := s.cache.Set(reqCtx, cacheKey, validatedCtx, cacheTTL); err != nil {
		s.logger.Error(reqCtx, "Failed to cache validated token", "cache_key", cacheKey, "error", err.Error())
	}
	s.logger.Info(reqCtx, "Token decrypted, validated, and cached successfully", "cache_key", cacheKey)
	return validatedCtx, nil
}
func (s *AuthService) ProcessAdminToken(reqCtx context.Context, tokenB64 string) (*domain.AdminUserContext, error) {
	cacheKey := rediskeys.TokenCacheKey("admin_" + tokenB64)
	cachedAdminCtx, err := s.adminCache.Get(reqCtx, cacheKey)
	if err == nil && cachedAdminCtx != nil {
		if time.Now().After(cachedAdminCtx.ExpiresAt) {
			s.logger.Warn(reqCtx, "Cached admin token found but was expired", "cache_key", cacheKey, "expires_at", cachedAdminCtx.ExpiresAt)
		} else {
			s.logger.Debug(reqCtx, "Admin token found in cache and is valid", "cache_key", cacheKey)
			return cachedAdminCtx, nil
		}
	} else if err != nil && !errors.Is(err, ErrCacheMiss) {
		s.logger.Error(reqCtx, "Error retrieving admin token from cache", "cache_key", cacheKey, "error", err.Error())
	}
	s.logger.Debug(reqCtx, "Admin token not found in cache or cache error, proceeding to decrypt", "cache_key", cacheKey)
	aesKeyHex := s.config.Get().Auth.AdminTokenAESKey
	if aesKeyHex == "" {
		s.logger.Error(reqCtx, "AdminTokenAESKey not configured", "config_key", "auth.admin_token_aes_key")
		return nil, errors.New("application not configured for admin token decryption")
	}
	decryptedPayload, err := crypto.DecryptAESGCM(aesKeyHex, tokenB64)
	if err != nil {
		s.logger.Warn(reqCtx, "Admin token decryption failed", "error", err.Error())
		return nil, err
	}
	validatedAdminCtx, err := s.ParseAndValidateAdminDecryptedToken(decryptedPayload, tokenB64)
	if err != nil {
		s.logger.Warn(reqCtx, "Decrypted admin token failed validation", "error", err.Error())
		return nil, err
	}
	cacheTTLSeconds := s.config.Get().Auth.AdminTokenCacheTTLSeconds
	cacheTTL := time.Duration(cacheTTLSeconds) * time.Second
	if cacheTTLSeconds == 0 {
		cacheTTL = 60 * time.Second
		s.logger.Debug(reqCtx, "auth.adminTokenCacheTTLSeconds not configured or zero, using default 60s", "cache_key", cacheKey)
	}
	if err := s.adminCache.Set(reqCtx, cacheKey, validatedAdminCtx, cacheTTL); err != nil {
		s.logger.Error(reqCtx, "Failed to cache validated admin token", "cache_key", cacheKey, "error", err.Error())
	}
	s.logger.Info(reqCtx, "Admin token decrypted, validated, and cached successfully", "cache_key", cacheKey, "admin_id", validatedAdminCtx.AdminID)
	return validatedAdminCtx, nil
}
```

## File: internal/bootstrap/wire.go
```go
package bootstrap
import (
	"context"
	"github.com/google/wire"
)
func InitializeApp(ctx context.Context) (*App, func(), error) {
	wire.Build(ProviderSet)
	return nil, nil, nil
}
```

## File: internal/domain/cache.go
```go
package domain
import (
	"context"
	"time"
)
type TokenCacheStore interface {
	Get(ctx context.Context, key string) (*AuthenticatedUserContext, error)
	Set(ctx context.Context, key string, value *AuthenticatedUserContext, ttl time.Duration) error
}
type AdminTokenCacheStore interface {
	Get(ctx context.Context, key string) (*AdminUserContext, error)
	Set(ctx context.Context, key string, value *AdminUserContext, ttl time.Duration) error
}
```

## File: internal/domain/errors.go
```go
package domain
import (
	"encoding/json"
	"net/http"
)
type ErrorCode string
const (
	ErrInvalidAPIKey       ErrorCode = "InvalidAPIKey"
	ErrInvalidToken        ErrorCode = "InvalidToken"
	ErrSessionConflict     ErrorCode = "SessionConflict"
	ErrSubscriptionFailure ErrorCode = "SubscriptionFailure"
	ErrRateLimitExceeded   ErrorCode = "RateLimitExceeded"
	ErrBadRequest          ErrorCode = "BadRequest"
	ErrInternal            ErrorCode = "InternalServerError"
	ErrMethodNotAllowed    ErrorCode = "E4005"
	ErrUnauthorized ErrorCode = "E4001"
	ErrForbidden    ErrorCode = "E4003"
)
type ErrorResponse struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
}
func NewErrorResponse(code ErrorCode, message string, details string) ErrorResponse {
	return ErrorResponse{
		Code:    code,
		Message: message,
		Details: details,
	}
}
func (er ErrorResponse) WriteJSON(w http.ResponseWriter, httpStatusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(er)
}
```

## File: pkg/contextkeys/keys.go
```go
package contextkeys
type contextKey string
const (
	RequestIDKey contextKey = "request_id"
	EventIDKey contextKey = "event_id"
	UserIDKey contextKey = "user_id"
	CompanyIDKey contextKey = "company_id"
	AgentIDKey contextKey = "agent_id"
	IsAdminKey contextKey = "is_admin"
	AuthUserContextKey contextKey = "auth_user_context"
	AdminUserContextKey contextKey = "admin_user_context"
)
func (c contextKey) String() string {
	return string(c)
}
```

## File: pkg/crypto/aesgcm.go
```go
package crypto
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)
var (
	ErrInvalidAESKeySize     = errors.New("invalid AES key size")
	ErrInvalidTokenFormat    = errors.New("invalid token format, expecting base64 encoded nonce+ciphertext")
	ErrCiphertextTooShort    = errors.New("ciphertext too short, cannot extract nonce")
	ErrTokenDecryptionFailed = errors.New("token decryption failed")
)
const (
	aes256KeyBytes = 32
	gcmNonceSizeBytes = 12
)
func DecryptAESGCM(aesKeyHex string, tokenB64 string) ([]byte, error) {
	key, err := hex.DecodeString(aesKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key from hex: %w", err)
	}
	if len(key) != aes256KeyBytes {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidAESKeySize, aes256KeyBytes, len(key))
	}
	encryptedToken, err := base64.URLEncoding.DecodeString(tokenB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTokenFormat, err)
	}
	if len(encryptedToken) < gcmNonceSizeBytes {
		return nil, fmt.Errorf("%w: length %d, minimum %d", ErrCiphertextTooShort, len(encryptedToken), gcmNonceSizeBytes)
	}
	nonce := encryptedToken[:gcmNonceSizeBytes]
	ciphertext := encryptedToken[gcmNonceSizeBytes:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrTokenDecryptionFailed
	}
	return plaintext, nil
}
func EncryptAESGCM(aesKeyHex string, plaintext []byte) (string, error) {
	key, err := hex.DecodeString(aesKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode AES key from hex: %w", err)
	}
	if len(key) != aes256KeyBytes {
		return "", fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidAESKeySize, aes256KeyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher block: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	nonce := make([]byte, gcmNonceSizeBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertextWithTag := aesgcm.Seal(nil, nonce, plaintext, nil)
	encryptedPayload := append(nonce, ciphertextWithTag...)
	return base64.URLEncoding.EncodeToString(encryptedPayload), nil
}
```

## File: pkg/rediskeys/keys.go
```go
package rediskeys
import (
	"fmt"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
)
func TokenCacheKey(rawToken string) string {
	hashedToken := crypto.Sha256Hex(rawToken)
	return fmt.Sprintf("token_cache:%s", hashedToken)
}
func SessionKey(company, agent, user string) string {
	return fmt.Sprintf("session:%s:%s:%s", company, agent, user)
}
func RouteKeyChats(company, agent string) string {
	return fmt.Sprintf("route:%s:%s:chats", company, agent)
}
func RouteKeyMessages(company, agent, chatID string) string {
	return fmt.Sprintf("route:%s:%s:messages:%s", company, agent, chatID)
}
func SessionKillChannelKey(company, agent, user string) string {
	return fmt.Sprintf("session_kill:%s:%s:%s", company, agent, user)
}
func AdminSessionKey(adminID string) string {
	return fmt.Sprintf("session:admin:%s", adminID)
}
func AdminSessionKillChannelKey(adminID string) string {
	return fmt.Sprintf("session_kill:admin:%s", adminID)
}
```

## File: go.mod
```
module gitlab.com/timkado/api/daisi-ws-service

toolchain go1.23.9

go 1.23.0

require (
	github.com/coder/websocket v1.8.13
	github.com/fsnotify/fsnotify v1.8.0
	github.com/google/wire v0.6.0
	github.com/nats-io/nats.go v1.42.0
	github.com/prometheus/client_golang v1.22.0
	github.com/redis/go-redis/v9 v9.8.0
	github.com/spf13/viper v1.20.1
	go.uber.org/zap v1.27.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/nkeys v0.4.11 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
```

## File: config/config.yaml
```yaml
server:
  http_port: 8080
  grpc_port: 50051
nats:
  url: "nats://nats:4222"
  stream_name: "wa_stream"
  consumer_name: "ws_fanout"
redis:
  address: "redis:6379"
log:
  level: "info"
auth:
  secret_token: "YOUR_32_CHAR_DAISI_WS_SERVICE_SECRET_TOKEN_HERE"
  token_aes_key: "YOUR_64_CHAR_HEX_ENCODED_AES256_KEY_FOR_TOKENS_HERE"
  token_generation_admin_key: "YOUR_32_CHAR_DEDICATED_TOKEN_GENERATION_ADMIN_KEY_HERE"
  token_cache_ttl_seconds: 30
  admin_token_aes_key: "YOUR_64_CHAR_HEX_ENCODED_AES256_KEY_FOR_ADMIN_TOKENS_HERE"
  admin_token_cache_ttl_seconds: 60
app:
  service_name: "daisi-ws-service"
  version: "1.0.0"
  ping_interval_seconds: 20
  shutdown_timeout_seconds: 30
  max_missed_pongs: 2
  session_ttl_seconds: 30
  route_ttl_seconds: 30
  ttl_refresh_interval_seconds: 10
  nats_max_ack_pending: 5000
  session_lock_retry_delay_ms: 250
```

## File: internal/adapters/websocket/router.go
```go
package websocket
import (
	"context"
	"net/http"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
type Router struct {
	logger         domain.Logger
	configProvider config.Provider
	authService    *application.AuthService
	wsHandler      http.Handler
}
func NewRouter(logger domain.Logger, cfgProvider config.Provider, authService *application.AuthService, wsHandler http.Handler) *Router {
	return &Router{
		logger:         logger,
		configProvider: cfgProvider,
		authService:    authService,
		wsHandler:      wsHandler,
	}
}
func (r *Router) RegisterRoutes(ctx context.Context, mux *http.ServeMux) {
	apiKeyAuthedHandler := middleware.APIKeyAuthMiddleware(r.configProvider, r.logger)(r.wsHandler)
	companyTokenAuthedHandler := middleware.CompanyTokenAuthMiddleware(r.authService, r.logger)(apiKeyAuthedHandler)
	mux.Handle("GET /ws/{company}/{agent}", companyTokenAuthedHandler)
	r.logger.Info(ctx, "WebSocket endpoint registered with API Key and Company Token authentication", "pattern", "GET /ws/{company}/{agent}")
}
```

## File: internal/application/connection_manager.go
```go
package application
import (
	"sync"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
type ConnectionManager struct {
	logger               domain.Logger
	configProvider       config.Provider
	sessionLocker        domain.SessionLockManager
	killSwitchPublisher  domain.KillSwitchPublisher
	killSwitchSubscriber domain.KillSwitchSubscriber
	activeConnections    sync.Map
	renewalStopChan chan struct{}
	renewalWg       sync.WaitGroup
}
func NewConnectionManager(
	logger domain.Logger,
	configProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPublisher domain.KillSwitchPublisher,
	killSwitchSubscriber domain.KillSwitchSubscriber,
) *ConnectionManager {
	return &ConnectionManager{
		logger:               logger,
		configProvider:       configProvider,
		sessionLocker:        sessionLocker,
		killSwitchPublisher:  killSwitchPublisher,
		killSwitchSubscriber: killSwitchSubscriber,
		activeConnections:    sync.Map{},
		renewalStopChan:      make(chan struct{}),
	}
}
```

## File: internal/application/connection_registry.go
```go
package application
import (
	"context"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
func (cm *ConnectionManager) RegisterConnection(sessionKey string, conn domain.ManagedConnection) {
	cm.activeConnections.Store(sessionKey, conn)
	metrics.IncrementActiveConnections()
	cm.logger.Info(conn.Context(), "WebSocket connection registered with ConnectionManager", "sessionKey", sessionKey, "remoteAddr", conn.RemoteAddr())
}
func (cm *ConnectionManager) DeregisterConnection(sessionKey string) {
	connVal, loaded := cm.activeConnections.LoadAndDelete(sessionKey)
	logCtx := context.Background()
	if loaded {
		metrics.DecrementActiveConnections()
		if managedConn, ok := connVal.(domain.ManagedConnection); ok {
			logCtx = managedConn.Context()
			cm.logger.Info(logCtx, "WebSocket connection deregistered from ConnectionManager", "sessionKey", sessionKey, "remoteAddr", managedConn.RemoteAddr())
		} else {
			cm.logger.Warn(logCtx, "Deregistered a non-ManagedConnection connection from map", "sessionKey", sessionKey)
		}
		podID := cm.configProvider.Get().Server.PodID
		if podID != "" {
			released, err := cm.sessionLocker.ReleaseLock(logCtx, sessionKey, podID)
			if err != nil {
				cm.logger.Error(logCtx, "Failed to release session lock on deregister", "sessionKey", sessionKey, "podID", podID, "error", err.Error())
			} else if released {
				cm.logger.Info(logCtx, "Successfully released session lock on deregister", "sessionKey", sessionKey, "podID", podID)
			} else {
				cm.logger.Warn(logCtx, "Could not release session lock on deregister (may not exist or not owned by this pod)", "sessionKey", sessionKey, "podID", podID)
			}
		} else {
			cm.logger.Error(logCtx, "PodID is not configured. Cannot release session lock on deregister.", "sessionKey", sessionKey)
		}
	} else {
		cm.logger.Debug(logCtx, "Attempted to deregister a connection not found in map", "sessionKey", sessionKey)
	}
}
```

## File: internal/application/session_locking.go
```go
package application
import (
	"context"
	"fmt"
	"time"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)
func (cm *ConnectionManager) SessionLocker() domain.SessionLockManager {
	return cm.sessionLocker
}
func (cm *ConnectionManager) AcquireSessionLockOrNotify(ctx context.Context, companyID, agentID, userID string) (bool, error) {
	cfg := cm.configProvider.Get()
	podID := cfg.Server.PodID
	if podID == "" {
		cm.logger.Error(ctx, "PodID is not configured. Session locking/notification will not work correctly.", "operation", "AcquireSessionLockOrNotify")
		return false, fmt.Errorf("podID is not configured")
	}
	sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	cm.logger.Info(ctx, "Attempting to acquire session lock",
		"sessionKey", sessionKey,
		"podID", podID,
		"ttlSeconds", sessionTTL.Seconds(),
	)
	acquired, err := cm.sessionLocker.AcquireLock(ctx, sessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire session lock from store",
			"error", err.Error(),
			"sessionKey", sessionKey,
		)
		return false, fmt.Errorf("failed to acquire session lock: %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Session lock acquired successfully",
			"sessionKey", sessionKey,
			"podID", podID,
		)
		return true, nil
	}
	cm.logger.Warn(ctx, "Failed to acquire session lock (already held). Publishing kill message.",
		"sessionKey", sessionKey,
		"newPodIDAttempting", podID,
	)
	killChannel := rediskeys.SessionKillChannelKey(companyID, agentID, userID)
	killMsg := domain.KillSwitchMessage{NewPodID: podID}
	if pubErr := cm.killSwitchPublisher.PublishSessionKill(ctx, killChannel, killMsg); pubErr != nil {
		cm.logger.Error(ctx, "Failed to publish session kill message",
			"channel", killChannel,
			"error", pubErr.Error(),
		)
	}
	cm.logger.Info(ctx, "Attempting retry for session lock acquisition after kill message", "sessionKey", sessionKey)
	retryDelayMs := cfg.App.SessionLockRetryDelayMs
	if retryDelayMs <= 0 {
		retryDelayMs = 250
		cm.logger.Warn(ctx, "SessionLockRetryDelayMs not configured or invalid, defaulting", "default_ms", retryDelayMs, "sessionKey", sessionKey)
	}
	retryDelayDuration := time.Duration(retryDelayMs) * time.Millisecond
	select {
	case <-time.After(retryDelayDuration):
		cm.logger.Debug(ctx, "Retry delay completed", "sessionKey", sessionKey, "delay", retryDelayDuration)
	case <-ctx.Done():
		cm.logger.Warn(ctx, "Context cancelled during retry delay for session lock", "sessionKey", sessionKey, "error", ctx.Err())
		return false, ctx.Err()
	}
	cm.logger.Info(ctx, "Retrying AcquireLock (SETNX) for session", "sessionKey", sessionKey, "podID", podID)
	acquired, err = cm.sessionLocker.AcquireLock(ctx, sessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to retry AcquireLock (SETNX)", "sessionKey", sessionKey, "error", err.Error())
		return false, fmt.Errorf("failed to retry AcquireLock (SETNX): %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Session lock acquired successfully on SETNX retry", "sessionKey", sessionKey, "podID", podID)
		return true, nil
	}
	cm.logger.Warn(ctx, "SETNX retry failed. Attempting ForceAcquireLock (SET) for session.", "sessionKey", sessionKey, "podID", podID)
	acquired, err = cm.sessionLocker.ForceAcquireLock(ctx, sessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to ForceAcquireLock (SET)", "sessionKey", sessionKey, "error", err.Error())
		return false, fmt.Errorf("failed to ForceAcquireLock (SET): %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Session lock acquired successfully using ForceAcquireLock (SET)", "sessionKey", sessionKey, "podID", podID)
		return true, nil
	}
	cm.logger.Error(ctx, "All attempts to acquire session lock failed, including ForceAcquireLock.", "sessionKey", sessionKey)
	return false, fmt.Errorf("all attempts to acquire session lock failed for key %s", sessionKey)
}
func (cm *ConnectionManager) AcquireAdminSessionLockOrNotify(ctx context.Context, adminID string) (bool, error) {
	cfg := cm.configProvider.Get()
	podID := cfg.Server.PodID
	if podID == "" {
		cm.logger.Error(ctx, "PodID is not configured. Admin session locking will not work correctly.", "operation", "AcquireAdminSessionLockOrNotify")
		return false, fmt.Errorf("podID is not configured")
	}
	adminSessionKey := rediskeys.AdminSessionKey(adminID)
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	cm.logger.Info(ctx, "Attempting to acquire admin session lock",
		"adminSessionKey", adminSessionKey,
		"podID", podID,
		"ttlSeconds", sessionTTL.Seconds(),
	)
	acquired, err := cm.sessionLocker.AcquireLock(ctx, adminSessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire admin session lock from store", "error", err.Error(), "adminSessionKey", adminSessionKey)
		return false, fmt.Errorf("failed to acquire admin session lock: %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Admin session lock acquired successfully", "adminSessionKey", adminSessionKey, "podID", podID)
		return true, nil
	}
	cm.logger.Warn(ctx, "Failed to acquire admin session lock (already held). Publishing admin kill message.",
		"adminSessionKey", adminSessionKey,
		"newPodIDAttempting", podID,
	)
	killChannel := rediskeys.AdminSessionKillChannelKey(adminID)
	killMsg := domain.KillSwitchMessage{NewPodID: podID}
	if pubErr := cm.killSwitchPublisher.PublishSessionKill(ctx, killChannel, killMsg); pubErr != nil {
		cm.logger.Error(ctx, "Failed to publish admin session kill message", "channel", killChannel, "error", pubErr.Error())
	}
	cm.logger.Info(ctx, "Attempting retry for admin session lock acquisition after kill message", "adminSessionKey", adminSessionKey)
	retryDelayMs := cfg.App.SessionLockRetryDelayMs
	if retryDelayMs <= 0 {
		retryDelayMs = 250
		cm.logger.Warn(ctx, "SessionLockRetryDelayMs not configured or invalid for admin, defaulting", "default_ms", retryDelayMs, "adminSessionKey", adminSessionKey)
	}
	retryDelayDuration := time.Duration(retryDelayMs) * time.Millisecond
	select {
	case <-time.After(retryDelayDuration):
		cm.logger.Debug(ctx, "Admin retry delay completed", "adminSessionKey", adminSessionKey, "delay", retryDelayDuration)
	case <-ctx.Done():
		cm.logger.Warn(ctx, "Context cancelled during retry delay for admin session lock", "adminSessionKey", adminSessionKey, "error", ctx.Err())
		return false, ctx.Err()
	}
	cm.logger.Info(ctx, "Retrying AcquireLock (SETNX) for admin session", "adminSessionKey", adminSessionKey, "podID", podID)
	acquired, err = cm.sessionLocker.AcquireLock(ctx, adminSessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to retry AcquireLock (SETNX) for admin session", "adminSessionKey", adminSessionKey, "error", err.Error())
		return false, fmt.Errorf("failed to retry AcquireLock (SETNX) for admin: %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Admin session lock acquired successfully on SETNX retry", "adminSessionKey", adminSessionKey, "podID", podID)
		return true, nil
	}
	cm.logger.Warn(ctx, "Admin SETNX retry failed. Attempting ForceAcquireLock (SET) for admin session.", "adminSessionKey", adminSessionKey, "podID", podID)
	acquired, err = cm.sessionLocker.ForceAcquireLock(ctx, adminSessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to ForceAcquireLock (SET) for admin session", "adminSessionKey", adminSessionKey, "error", err.Error())
		return false, fmt.Errorf("failed to ForceAcquireLock (SET) for admin: %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Admin session lock acquired successfully using ForceAcquireLock (SET)", "adminSessionKey", adminSessionKey, "podID", podID)
		return true, nil
	}
	cm.logger.Error(ctx, "All attempts to acquire admin session lock failed, including ForceAcquireLock.", "adminSessionKey", adminSessionKey)
	return false, fmt.Errorf("all attempts to acquire admin session lock failed for key %s", adminSessionKey)
}
```

## File: internal/application/session_renewal.go
```go
package application
import (
	"context"
	"time"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)
func (cm *ConnectionManager) StartSessionRenewalLoop(appCtx context.Context) {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	podID := cfg.Server.PodID
	if renewalInterval <= 0 {
		cm.logger.Warn(appCtx, "Session lock renewal interval is not configured or invalid; renewal loop will not start.", "intervalSeconds", cfg.App.TTLRefreshIntervalSeconds)
		return
	}
	if sessionTTL <= 0 {
		cm.logger.Warn(appCtx, "Session lock TTL is not configured or invalid; renewal logic might be ineffective.", "ttlSeconds", cfg.App.SessionTTLSeconds)
	}
	if podID == "" {
		cm.logger.Error(appCtx, "PodID is not configured. Session lock renewal will not work correctly.")
		return
	}
	cm.logger.Info(appCtx, "Starting session renewal loop", "renewalInterval", renewalInterval.String(), "sessionTTL", sessionTTL.String(), "podID", podID)
	cm.renewalWg.Add(1)
	safego.Execute(appCtx, cm.logger, "SessionRenewalLoop", func() {
		defer cm.renewalWg.Done()
		ticker := time.NewTicker(renewalInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cm.logger.Debug(appCtx, "Session renewal tick: attempting to renew active session locks")
				var keysToRenew []string
				cm.activeConnections.Range(func(key, value interface{}) bool {
					sessionKey, ok := key.(string)
					if ok {
						keysToRenew = append(keysToRenew, sessionKey)
					}
					return true
				})
				if len(keysToRenew) == 0 {
					cm.logger.Debug(appCtx, "No active session locks to renew this tick.")
					continue
				}
				cm.logger.Debug(appCtx, "Found active session locks to renew", "count", len(keysToRenew))
				for _, sessionKey := range keysToRenew {
					renewalCtx, cancel := context.WithTimeout(appCtx, 5*time.Second)
					refreshed, err := cm.sessionLocker.RefreshLock(renewalCtx, sessionKey, podID, sessionTTL)
					if err != nil {
						cm.logger.Error(renewalCtx, "Error refreshing session lock", "sessionKey", sessionKey, "podID", podID, "error", err.Error())
					} else if refreshed {
						cm.logger.Debug(renewalCtx, "Successfully refreshed session lock", "sessionKey", sessionKey, "podID", podID, "newTTL", sessionTTL.String())
					} else {
						cm.logger.Warn(renewalCtx, "Failed to refresh session lock (not owned or expired)", "sessionKey", sessionKey, "podID", podID)
					}
					cancel()
				}
			case <-cm.renewalStopChan:
				cm.logger.Info(appCtx, "Session renewal loop stopping as requested.")
				return
			case <-appCtx.Done():
				cm.logger.Info(appCtx, "Session renewal loop stopping due to application context cancellation.")
				return
			}
		}
	})
}
func (cm *ConnectionManager) StopSessionRenewalLoop() {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	if renewalInterval <= 0 || cfg.Server.PodID == "" { // Check if loop was started
		cm.logger.Info(context.Background(), "Session renewal loop was not started or podID not set, nothing to stop.")
		return
	}
	cm.logger.Info(context.Background(), "Attempting to stop session renewal loop...")
	close(cm.renewalStopChan)
	cm.renewalWg.Wait()
	cm.logger.Info(context.Background(), "Session renewal loop stopped.")
}
```

## File: internal/domain/auth.go
```go
package domain
import "time"
type AuthenticatedUserContext struct {
	CompanyID string    `json:"company_id"`
	AgentID   string    `json:"agent_id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"-"`
}
type AdminUserContext struct {
	AdminID              string `json:"admin_id"`
	CompanyIDRestriction string `json:"company_id_restriction,omitempty"`
	SubscribedCompanyID string    `json:"subscribed_company_id,omitempty"`
	SubscribedAgentID   string    `json:"subscribed_agent_id,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	Token               string    `json:"-"`
}
```

## File: internal/adapters/config/config.go
```go
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
type ServerConfig struct {
	HTTPPort int    `mapstructure:"http_port"`
	GRPCPort int    `mapstructure:"grpc_port"`
	PodID    string `mapstructure:"pod_id"`
}
type NATSConfig struct {
	URL          string `mapstructure:"url"`
	StreamName   string `mapstructure:"stream_name"`
	ConsumerName string `mapstructure:"consumer_name"`
}
type RedisConfig struct {
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}
type LogConfig struct {
	Level string `mapstructure:"level"`
}
type AuthConfig struct {
	SecretToken               string `mapstructure:"secret_token"`
	TokenAESKey               string `mapstructure:"token_aes_key"`
	TokenGenerationAdminKey   string `mapstructure:"token_generation_admin_key"`
	TokenCacheTTLSeconds      int    `mapstructure:"token_cache_ttl_seconds"`
	AdminTokenAESKey          string `mapstructure:"admin_token_aes_key"`
	AdminTokenCacheTTLSeconds int    `mapstructure:"admin_token_cache_ttl_seconds"`
}
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
	SessionLockRetryDelayMs   int    `mapstructure:"session_lock_retry_delay_ms"`
}
type Config struct {
	Server ServerConfig `mapstructure:"server"`
	NATS   NATSConfig   `mapstructure:"nats"`
	Redis  RedisConfig  `mapstructure:"redis"`
	Log    LogConfig    `mapstructure:"log"`
	Auth   AuthConfig   `mapstructure:"auth"`
	App    AppConfig    `mapstructure:"app"`
}
type Provider interface {
	Get() *Config
}
type viperProvider struct {
	config *Config
	logger *zap.Logger
}
func NewViperProvider(appCtx context.Context, logger *zap.Logger) (Provider, error) {
	cfg := &Config{}
	v := viper.New()
	v.SetConfigName(os.Getenv("VIPER_CONFIG_NAME"))
	v.SetConfigType("yaml")
	v.AddConfigPath(os.Getenv("VIPER_CONFIG_PATH"))
	v.AddConfigPath(".")
	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Warn("Config file not found; relying on defaults and environment variables", zap.Error(err))
		} else {
			logger.Error("Failed to read config file", zap.Error(err))
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}
	if err := v.Unmarshal(cfg); err != nil {
		logger.Error("Failed to unmarshal config", zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	p := &viperProvider{
		config: cfg,
		logger: logger,
	}
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
				return
			}
		}
	}()
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
func (p *viperProvider) Get() *Config {
	return p.config
}
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
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
	}
	return v, nil
}
```

## File: internal/application/kill_switch.go
```go
package application
import (
	"context"
	"fmt"
	"strings"
	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)
const (
	sessionKillChannelPrefix      = "session_kill:"
	adminSessionKillChannelPrefix = "session_kill:admin:"
)
func (cm *ConnectionManager) handleKillSwitchMessage(channel string, message domain.KillSwitchMessage) error {
	ctx := context.Background()
	cm.logger.Info(ctx, "Received user kill switch message via pub/sub",
		"channel", channel,
		"newPodIDInMessage", message.NewPodID,
	)
	currentPodID := cm.configProvider.Get().Server.PodID
	if message.NewPodID == currentPodID {
		cm.logger.Info(ctx, "User kill message originated from this pod or is for a session this pod just acquired. No action needed.", "channel", channel, "currentPodID", currentPodID)
		return nil
	}
	if !strings.HasPrefix(channel, sessionKillChannelPrefix) || strings.HasPrefix(channel, adminSessionKillChannelPrefix) {
		cm.logger.Error(ctx, "handleKillSwitchMessage received message on unexpected channel format or admin channel", "channel", channel)
		return fmt.Errorf("invalid user channel format for handleKillSwitchMessage: %s", channel)
	}
	partsStr := strings.TrimPrefix(channel, sessionKillChannelPrefix)
	parts := strings.Split(partsStr, ":")
	if len(parts) != 3 {
		cm.logger.Error(ctx, "Could not parse company/agent/user from user kill switch channel", "channel", channel, "parsedParts", partsStr)
		return fmt.Errorf("could not parse identifiers from user channel: %s", channel)
	}
	companyID, agentID, userID := parts[0], parts[1], parts[2]
	sessionKey := rediskeys.SessionKey(companyID, agentID, userID)
	cm.logger.Info(ctx, "Processing user kill message for potential local connection termination",
		"sessionKey", sessionKey,
		"messageNewPodID", message.NewPodID,
		"currentPodID", currentPodID)
	val, exists := cm.activeConnections.Load(sessionKey)
	if !exists {
		cm.logger.Info(ctx, "No active local user connection found for session key, no action needed.", "sessionKey", sessionKey)
		return nil
	}
	managedConn, ok := val.(domain.ManagedConnection)
	if !ok {
		cm.logger.Error(ctx, "Found non-ManagedConnection type in activeConnections map for user session key", "sessionKey", sessionKey)
		cm.DeregisterConnection(sessionKey)
		return fmt.Errorf("invalid type in activeConnections map for user key %s", sessionKey)
	}
	logCtx := managedConn.Context()
	cm.logger.Warn(logCtx, "Closing local user WebSocket connection due to session conflict (taken over by another pod)",
		"sessionKey", sessionKey,
		"remoteAddr", managedConn.RemoteAddr(),
		"conflictingPodID", message.NewPodID,
	)
	if err := managedConn.Close(websocket.StatusCode(4402), "SessionConflict: Session taken over by another connection"); err != nil {
		cm.logger.Error(logCtx, "Error closing user WebSocket connection after session conflict",
			"sessionKey", sessionKey,
			"remoteAddr", managedConn.RemoteAddr(),
			"error", err.Error(),
		)
	}
	cm.DeregisterConnection(sessionKey)
	return nil
}
func (cm *ConnectionManager) handleAdminKillSwitchMessage(channel string, message domain.KillSwitchMessage) error {
	ctx := context.Background()
	cm.logger.Info(ctx, "Received admin kill switch message via pub/sub",
		"channel", channel,
		"newPodIDInMessage", message.NewPodID,
	)
	currentPodID := cm.configProvider.Get().Server.PodID
	if message.NewPodID == currentPodID {
		cm.logger.Info(ctx, "Admin kill message originated from this pod or is for a session this pod just acquired. No action needed.", "channel", channel, "currentPodID", currentPodID)
		return nil
	}
	if !strings.HasPrefix(channel, adminSessionKillChannelPrefix) {
		cm.logger.Error(ctx, "handleAdminKillSwitchMessage received message on unexpected channel format", "channel", channel)
		return fmt.Errorf("invalid admin channel format for handleAdminKillSwitchMessage: %s", channel)
	}
	adminID := strings.TrimPrefix(channel, adminSessionKillChannelPrefix)
	adminSessionKey := rediskeys.AdminSessionKey(adminID)
	cm.logger.Info(ctx, "Processing admin kill message for potential local admin connection termination",
		"adminSessionKey", adminSessionKey,
		"messageNewPodID", message.NewPodID,
		"currentPodID", currentPodID)
	val, exists := cm.activeConnections.Load(adminSessionKey)
	if !exists {
		cm.logger.Info(ctx, "No active local admin connection found for session key, no action needed.", "adminSessionKey", adminSessionKey)
		return nil
	}
	managedConn, ok := val.(domain.ManagedConnection)
	if !ok {
		cm.logger.Error(ctx, "Found non-ManagedConnection type in activeConnections map for admin session key", "adminSessionKey", adminSessionKey)
		cm.DeregisterConnection(adminSessionKey)
		return fmt.Errorf("invalid type in activeConnections map for admin key %s", adminSessionKey)
	}
	logCtx := managedConn.Context()
	cm.logger.Warn(logCtx, "Closing local admin WebSocket connection due to session conflict (taken over by another pod)",
		"adminSessionKey", adminSessionKey,
		"remoteAddr", managedConn.RemoteAddr(),
		"conflictingPodID", message.NewPodID,
	)
	if err := managedConn.Close(websocket.StatusCode(4402), "AdminSessionConflict: Session taken over by another connection"); err != nil {
		cm.logger.Error(logCtx, "Error closing admin WebSocket connection after session conflict",
			"adminSessionKey", adminSessionKey,
			"remoteAddr", managedConn.RemoteAddr(),
			"error", err.Error(),
		)
	}
	cm.DeregisterConnection(adminSessionKey)
	return nil
}
func (cm *ConnectionManager) StartKillSwitchListener(ctx context.Context) {
	cm.logger.Info(ctx, "Starting User KillSwitch listener...")
	safego.Execute(ctx, cm.logger, "UserKillSwitchSubscriberLoop", func() {
		pattern := rediskeys.SessionKillChannelKey("*", "*", "*")
		cm.logger.Info(ctx, "User KillSwitch listener subscribing to pattern", "pattern", pattern)
		err := cm.killSwitchSubscriber.SubscribeToSessionKillPattern(ctx, pattern, cm.handleKillSwitchMessage)
		if err != nil {
			if ctx.Err() == context.Canceled {
				cm.logger.Info(ctx, "User KillSwitch subscriber stopped due to context cancellation.")
			} else {
				cm.logger.Error(ctx, "User KillSwitch subscriber failed or terminated", "error", err.Error())
			}
		}
		cm.logger.Info(ctx, "ConnectionManager User KillSwitch listener goroutine finished.")
	})
}
func (cm *ConnectionManager) StartAdminKillSwitchListener(ctx context.Context) {
	cm.logger.Info(ctx, "Starting Admin KillSwitch listener...")
	safego.Execute(ctx, cm.logger, "AdminKillSwitchSubscriberLoop", func() {
		pattern := rediskeys.AdminSessionKillChannelKey("*")
		cm.logger.Info(ctx, "Admin KillSwitch listener subscribing to pattern", "pattern", pattern)
		err := cm.killSwitchSubscriber.SubscribeToSessionKillPattern(ctx, pattern, cm.handleAdminKillSwitchMessage)
		if err != nil {
			if ctx.Err() == context.Canceled {
				cm.logger.Info(ctx, "Admin KillSwitch subscriber stopped due to context cancellation.")
			} else {
				cm.logger.Error(ctx, "Admin KillSwitch subscriber failed or terminated", "error", err.Error())
			}
		}
		cm.logger.Info(ctx, "ConnectionManager Admin KillSwitch listener goroutine finished.")
	})
}
func (cm *ConnectionManager) StopKillSwitchListener() error {
	cm.logger.Info(context.Background(), "Stopping all KillSwitch listeners (via shared subscriber Close)... ")
	if cm.killSwitchSubscriber != nil {
		return cm.killSwitchSubscriber.Close()
	}
	return nil
}
func (cm *ConnectionManager) StopAdminKillSwitchListener() error {
	cm.logger.Info(context.Background(), "Stopping Admin KillSwitch listener called - this is a no-op as StopKillSwitchListener closes the shared subscriber.")
	return nil
}
```

## File: internal/bootstrap/wire_gen.go
```go
package bootstrap
import (
	"context"
)
func InitializeApp(ctx context.Context) (*App, func(), error) {
	logger, cleanup, err := InitialZapLoggerProvider()
	if err != nil {
		return nil, nil, err
	}
	provider, err := ConfigProvider(ctx, logger)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	domainLogger, err := LoggerProvider(provider)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	serveMux := HTTPServeMuxProvider()
	server := HTTPGracefulServerProvider(provider, serveMux)
	handlerFunc := GenerateTokenHandlerProvider(provider, domainLogger)
	tokenGenerationMiddleware := TokenGenerationAuthMiddlewareProvider(provider, domainLogger)
	client, cleanup2, err := RedisClientProvider(provider, domainLogger)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	tokenCacheStore := TokenCacheStoreProvider(client, domainLogger)
	adminTokenCacheStore := AdminTokenCacheStoreProvider(client, domainLogger)
	authService := AuthServiceProvider(domainLogger, provider, tokenCacheStore, adminTokenCacheStore)
	sessionLockManager := SessionLockManagerProvider(client, domainLogger)
	killSwitchPubSubAdapter := KillSwitchPubSubAdapterProvider(client, domainLogger)
	connectionManager := ConnectionManagerProvider(domainLogger, provider, sessionLockManager, killSwitchPubSubAdapter, killSwitchPubSubAdapter)
	consumerAdapter, cleanup3, err := NatsConsumerAdapterProvider(ctx, provider, domainLogger)
	if err != nil {
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	handler := WebsocketHandlerProvider(domainLogger, provider, connectionManager, consumerAdapter)
	router := WebsocketRouterProvider(domainLogger, provider, authService, handler)
	adminAuthMiddleware := AdminAuthMiddlewareProvider(authService, domainLogger)
	adminHandler := AdminWebsocketHandlerProvider(domainLogger, provider, connectionManager, consumerAdapter)
	app, cleanup4, err := NewApp(provider, domainLogger, serveMux, server, handlerFunc, tokenGenerationMiddleware, router, connectionManager, consumerAdapter, adminAuthMiddleware, adminHandler)
	if err != nil {
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	return app, func() {
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
	}, nil
}
```

## File: internal/adapters/websocket/handler.go
```go
package websocket
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
	appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats"
)
type Handler struct {
	logger         domain.Logger
	configProvider config.Provider
	connManager    *application.ConnectionManager
	natsAdapter    *appnats.ConsumerAdapter
}
func NewHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter *appnats.ConsumerAdapter) *Handler {
	return &Handler{
		logger:         logger,
		configProvider: cfgProvider,
		connManager:    connManager,
		natsAdapter:    natsAdapter,
	}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pathCompany := r.PathValue("company")
	pathAgent := r.PathValue("agent")
	queryUser := r.URL.Query().Get("user")
	token := r.URL.Query().Get("token")
	authCtx, ok := r.Context().Value(contextkeys.AuthUserContextKey).(*domain.AuthenticatedUserContext)
	if !ok || authCtx == nil {
		h.logger.Error(r.Context(), "AuthenticatedUserContext not found after middleware chain",
			"path_company", pathCompany, "path_agent", pathAgent, "query_user", queryUser, "token_present", token != "",
		)
		// This should ideally not happen if middleware is correctly configured and run.
		// If it does, it's an internal server error because the auth context is missing.
		domain.NewErrorResponse(domain.ErrInternal, "Authentication context missing", "Server configuration error or middleware issue.").WriteJSON(w, http.StatusInternalServerError)
		return
	}
	if pathCompany == "" || pathAgent == "" { // Still validate path params for resource routing
		h.logger.Warn(r.Context(), "WebSocket upgrade failed: Missing company or agent in path",
			"remote_addr", r.RemoteAddr, "path", r.URL.Path,
			"auth_company_id", authCtx.CompanyID, "auth_agent_id", authCtx.AgentID, "auth_user_id", authCtx.UserID,
		)
		domain.NewErrorResponse(domain.ErrBadRequest, "Missing company or agent in path parameters.", "Ensure path is /ws/{company}/{agent}").WriteJSON(w, http.StatusBadRequest)
		return
	}
	if pathCompany != authCtx.CompanyID || pathAgent != authCtx.AgentID {
		h.logger.Warn(r.Context(), "Path parameters differ from token claims",
			"path_company", pathCompany, "token_company_id", authCtx.CompanyID,
			"path_agent", pathAgent, "token_agent_id", authCtx.AgentID,
			"token_user_id", authCtx.UserID,
		)
	}
	wsConnLifetimeCtx, cancelWsConnLifetimeCtx := context.WithCancel(r.Context())
	lockAcqCtx, lockAcqCancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer lockAcqCancel()
	acquired, err := h.connManager.AcquireSessionLockOrNotify(lockAcqCtx, authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	if err != nil {
		h.logger.Error(r.Context(), "Failed during session lock acquisition attempt", "error", err,
			"company", authCtx.CompanyID, "agent", authCtx.AgentID, "user", authCtx.UserID)
		domain.NewErrorResponse(domain.ErrInternal, "Failed to process session.", err.Error()).WriteJSON(w, http.StatusInternalServerError)
		cancelWsConnLifetimeCtx()
		return
	}
	if !acquired {
		h.logger.Warn(r.Context(), "Session lock not acquired (conflict or notification sent)",
			"company", authCtx.CompanyID, "agent", authCtx.AgentID, "user", authCtx.UserID)
		domain.NewErrorResponse(domain.ErrSessionConflict, "Session already active elsewhere.", "").WriteJSON(w, http.StatusConflict)
		cancelWsConnLifetimeCtx() // Important: cancel before returning
		return
	}
	// If lock acquired, proceed to upgrade.
	sessionKey := rediskeys.SessionKey(authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	h.logger.Info(r.Context(), "Session lock successfully acquired, proceeding to WebSocket upgrade", "sessionKey", sessionKey)
	var wrappedConn *Connection
	opts := websocket.AcceptOptions{
		Subprotocols: []string{"json.v1"},
		OnPongReceived: func(ctx context.Context, pongPayload []byte) {
			if wrappedConn != nil {
				h.logger.Debug(wrappedConn.Context(), "Pong received via AcceptOptions callback")
				wrappedConn.UpdateLastPongTime()
			}
		},
	}
	c, err := websocket.Accept(w, r, &opts)
	if err != nil {
		h.logger.Error(r.Context(), "WebSocket upgrade failed", "error", err,
			"company", authCtx.CompanyID, "agent", authCtx.AgentID, "user", authCtx.UserID)
		currentPodID := h.configProvider.Get().Server.PodID
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer releaseCancel()
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, sessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(r.Context(), "Failed to release session lock after upgrade failure", "sessionKey", sessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(r.Context(), "Successfully released session lock after upgrade failure", "sessionKey", sessionKey)
			}
		}
		cancelWsConnLifetimeCtx()
		return
	}
	wrappedConn = NewConnection(wsConnLifetimeCtx, cancelWsConnLifetimeCtx, c, r.RemoteAddr, h.logger, h.configProvider)
	h.logger.Info(wrappedConn.Context(), "WebSocket connection established",
		"remoteAddr", wrappedConn.RemoteAddr(),
		"subprotocol", c.Subprotocol(),
		"company", authCtx.CompanyID,
		"agent", authCtx.AgentID,
		"user", authCtx.UserID,
		"sessionKey", sessionKey)
	h.connManager.RegisterConnection(sessionKey, wrappedConn)
	defer func() {
		h.logger.Info(wrappedConn.Context(), "Connection management goroutine finished. Deregistering connection.", "sessionKey", sessionKey)
		h.connManager.DeregisterConnection(sessionKey)
		currentPodID := h.configProvider.Get().Server.PodID
		if currentPodID != "" {
			releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second) // Use a fresh, short-lived context
			defer releaseCancel()
			if released, releaseErr := h.connManager.SessionLocker().ReleaseLock(releaseCtx, sessionKey, currentPodID); releaseErr != nil {
				h.logger.Error(wrappedConn.Context(), "Failed to release session lock on connection close", "sessionKey", sessionKey, "error", releaseErr)
			} else if released {
				h.logger.Info(wrappedConn.Context(), "Successfully released session lock on connection close", "sessionKey", sessionKey)
			} else {
				h.logger.Warn(wrappedConn.Context(), "Failed to release session lock on connection close (lock not held or value mismatch)", "sessionKey", sessionKey, "pod_id_used_for_release", currentPodID)
			}
		}
	}()
	safego.Execute(wsConnLifetimeCtx, h.logger, fmt.Sprintf("WebSocketConnectionManager-%s", sessionKey), func() {
		h.manageConnection(wsConnLifetimeCtx, wrappedConn, authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	})
}
func (h *Handler) manageConnection(connCtx context.Context, conn *Connection, companyID, agentID, userID string) {
	defer conn.Close(websocket.StatusNormalClosure, "connection ended")
	h.logger.Info(connCtx, "WebSocket connection management started",
		"subprotocol", conn.UnderlyingConn().Subprotocol(),
		"remote_addr", conn.RemoteAddr(),
		"company_id", companyID,
		"agent_id", agentID,
		"user_id", userID)
	readyMessage := NewReadyMessage()
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to client", "error", err.Error())
		return
	}
	h.logger.Info(connCtx, "Sent 'ready' message to client")
	var natsSubscription *nats.Subscription
	if h.natsAdapter != nil {
		natsMsgHandler := func(msg *nats.Msg) {
			h.logger.Info(connCtx, "Received NATS message", "subject", msg.Subject, "data_len", len(msg.Data))
			var eventPayload domain.EnrichedEventPayload
			if err := json.Unmarshal(msg.Data, &eventPayload); err != nil {
				h.logger.Error(connCtx, "Failed to unmarshal NATS message into EnrichedEventPayload",
					"subject", msg.Subject, "error", err.Error(), "raw_data", string(msg.Data))
				if ackErr := msg.Ack(); ackErr != nil {
					h.logger.Error(connCtx, "Failed to ACK NATS message after unmarshal error", "subject", msg.Subject, "error", ackErr.Error())
				}
				return
			}
			wsMessage := NewEventMessage(eventPayload)
			if err := conn.WriteJSON(wsMessage); err != nil {
				h.logger.Error(connCtx, "Failed to forward NATS message to WebSocket client",
					"subject", msg.Subject, "event_id", eventPayload.EventID, "error", err.Error(),
				)
			}
			if ackErr := msg.Ack(); ackErr != nil {
				h.logger.Error(connCtx, "Failed to ACK NATS message after processing", "subject", msg.Subject, "event_id", eventPayload.EventID, "error", ackErr.Error())
			}
		}
		var subErr error
		natsSubscription, subErr = h.natsAdapter.SubscribeToChats(connCtx, companyID, agentID, natsMsgHandler)
		if subErr != nil {
			h.logger.Error(connCtx, "Failed to subscribe to NATS chat subject",
				"companyID", companyID, "agentID", agentID, "error", subErr.Error(),
			)
		} else {
			h.logger.Info(connCtx, "Successfully subscribed to NATS chat subject", "companyID", companyID, "agentID", agentID)
			defer func() {
				if natsSubscription != nil {
					h.logger.Info(connCtx, "Unsubscribing from NATS chat subject", "subject", natsSubscription.Subject)
					if unsubErr := natsSubscription.Drain(); unsubErr != nil {
						h.logger.Error(connCtx, "Error draining NATS subscription", "subject", natsSubscription.Subject, "error", unsubErr.Error())
					}
				}
			}()
		}
	} else {
		h.logger.Warn(connCtx, "NATS adapter is not available, cannot subscribe to chat events.")
	}
	appCfg := conn.config
	pingInterval := time.Duration(appCfg.PingIntervalSeconds) * time.Second
	pongWaitDuration := time.Duration(appCfg.PongWaitSeconds) * time.Second
	writeTimeout := time.Duration(appCfg.WriteTimeoutSeconds) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}
	if pingInterval > 0 {
		pinger := time.NewTicker(pingInterval)
		defer pinger.Stop()
		safego.Execute(connCtx, conn.logger, fmt.Sprintf("WebSocketPinger-%s", conn.RemoteAddr()), func() {
			for {
				select {
				case <-pinger.C:
					pingWriteCtx, pingCancel := context.WithTimeout(connCtx, writeTimeout)
					if err := conn.Ping(pingWriteCtx); err != nil {
						h.logger.Error(connCtx, "Failed to send ping", "error", err.Error())
						pingCancel()
						conn.Close(websocket.StatusAbnormalClosure, "Ping failure")
						return
					}
					pingCancel()
					h.logger.Debug(connCtx, "Sent ping")
					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr(), "lastPong", conn.LastPongTime())
						conn.Close(websocket.StatusPolicyViolation, "Pong timeout")
						return
					}
				case <-connCtx.Done():
					h.logger.Info(connCtx, "Connection context done in pinger, stopping pinger goroutine")
					return
				}
			}
		})
	} else {
		h.logger.Warn(connCtx, "Ping interval is not configured or invalid, server-initiated pings disabled.", "configured_interval_sec", appCfg.PingIntervalSeconds)
	}
	for {
		var readCtx context.Context
		var cancelRead context.CancelFunc
		if pongWaitDuration > 0 {
			readCtx, cancelRead = context.WithTimeout(connCtx, pongWaitDuration)
		} else {
			readCtx = connCtx
		}
		msgType, p, errRead := conn.ReadMessage(readCtx)
		if cancelRead != nil {
			cancelRead()
		}
		if errRead != nil {
			if errors.Is(readCtx.Err(), context.DeadlineExceeded) {
				h.logger.Warn(connCtx, "Pong timeout: No message received within pongWaitDuration. Closing connection.", "pong_wait_duration", pongWaitDuration)
				conn.Close(websocket.StatusPolicyViolation, "Pong timeout")
				return
			}
			closeStatus := websocket.CloseStatus(errRead)
			if closeStatus == websocket.StatusNormalClosure || closeStatus == websocket.StatusGoingAway {
				h.logger.Info(connCtx, "WebSocket connection closed by peer", "status_code", closeStatus)
			} else if errors.Is(errRead, context.Canceled) || connCtx.Err() == context.Canceled {
				h.logger.Info(connCtx, "WebSocket connection context canceled. Exiting manageConnection loop.")
			} else if closeStatus == -1 && (strings.Contains(strings.ToLower(errRead.Error()), "eof") || strings.Contains(strings.ToLower(errRead.Error()), "closed")) {
				h.logger.Info(connCtx, "WebSocket connection read EOF or already closed. Peer likely disconnected abruptly.", "error", errRead.Error())
			} else {
				h.logger.Error(connCtx, "Error reading from WebSocket", "error", errRead.Error(), "close_status_code", closeStatus)
			}
			return
		}
		h.logger.Debug(connCtx, "Received message from WebSocket",
			"type", msgType.String(),
			"payload_len", len(p),
		)
		if msgType == websocket.MessageText {
			var baseMsg BaseMessage
			if err := json.Unmarshal(p, &baseMsg); err != nil {
				h.logger.Error(connCtx, "Failed to unmarshal incoming message into BaseMessage", "error", err.Error())
				errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid message format", err.Error())
				if sendErr := conn.WriteJSON(NewErrorMessage(errResp)); sendErr != nil {
					h.logger.Error(connCtx, "Failed to send error message to client for invalid format", "error", sendErr.Error())
				}
				continue
			}
			switch baseMsg.Type {
			case MessageTypeSelectChat:
				h.handleSelectChatMessage(connCtx, conn, p, companyID, agentID, userID)
			default:
				h.handleUnknownMessage(connCtx, conn, baseMsg)
			}
		} else if msgType == websocket.MessageBinary {
			h.logger.Info(connCtx, "Received binary message, currently unhandled.")
		}
	}
}
func (h *Handler) handleSelectChatMessage(connCtx context.Context, conn *Connection, rawPayload []byte, companyID, agentID, userID string) {
	var selectChatPayload SelectChatMessagePayload
	if err := json.Unmarshal(rawPayload, &selectChatPayload); err != nil {
		h.logger.Error(connCtx, "Failed to unmarshal select_chat payload", "error", err, "company", companyID, "agent", agentID, "user", userID)
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", err.Error())
		if sendErr := conn.WriteJSON(NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for select_chat", "error", sendErr.Error())
		}
		return
	}
	h.logger.Info(connCtx, "Client selected chat", "chat_id", selectChatPayload.ChatID, "company", companyID, "agent", agentID, "user", userID)
}
func (h *Handler) handleUnknownMessage(connCtx context.Context, conn *Connection, baseMsg BaseMessage) {
	h.logger.Warn(connCtx, "Received unhandled message type from client", "type", baseMsg.Type)
	errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Unhandled message type", "Type: "+baseMsg.Type)
	if sendErr := conn.WriteJSON(NewErrorMessage(errResp)); sendErr != nil {
		h.logger.Error(connCtx, "Failed to send error message to client for unhandled type", "error", sendErr.Error())
	}
}
```

## File: internal/bootstrap/app.go
```go
package bootstrap
import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)
func (a *App) Run(ctx context.Context) error {
	version := "unknown"
	serviceName := "daisi-ws-service"
	if a.configProvider != nil && a.configProvider.Get() != nil {
		configApp := a.configProvider.Get().App
		if configApp.Version != "" {
			version = configApp.Version
		}
		if configApp.ServiceName != "" {
			serviceName = configApp.ServiceName
		}
	}
	a.logger.Info(ctx, "Starting application", "service_name", serviceName, "version", version)
	a.httpServeMux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		a.logger.Info(r.Context(), "Health check endpoint hit")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"OK"}`)
	})
	a.httpServeMux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		a.logger.Info(r.Context(), "Readiness check endpoint hit")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"READY"}`)
	})
	a.httpServeMux.Handle("GET /metrics", promhttp.Handler())
	a.logger.Info(ctx, "Prometheus metrics endpoint registered at /metrics")
	if a.wsRouter != nil {
		a.wsRouter.RegisterRoutes(ctx, a.httpServeMux)
	} else {
		a.logger.Warn(ctx, "WebSocket router is not initialized. WebSocket routes will not be available.")
	}
	if a.generateTokenHandler != nil && a.tokenGenerationMiddleware != nil {
		a.httpServeMux.Handle("POST /generate-token", a.tokenGenerationMiddleware(a.generateTokenHandler))
		a.logger.Info(ctx, "/generate-token endpoint registered")
	} else {
		a.logger.Error(ctx, "GenerateTokenHandler or TokenGenerationMiddleware not initialized. /generate-token endpoint will not be available.")
	}
	if a.adminWsHandler != nil && a.adminAuthMiddleware != nil && a.configProvider != nil {
		apiKeyAuth := middleware.APIKeyAuthMiddleware(a.configProvider, a.logger)
		adminAuthedHandler := a.adminAuthMiddleware(a.adminWsHandler)
		finalAdminWsHandler := apiKeyAuth(adminAuthedHandler)
		a.httpServeMux.Handle("GET /ws/admin", finalAdminWsHandler)
		a.logger.Info(ctx, "Admin WebSocket endpoint /ws/admin registered")
	} else {
		a.logger.Error(ctx, "AdminWsHandler, AdminAuthMiddleware, or ConfigProvider not initialized. /ws/admin endpoint will not be available.")
	}
	if a.connectionManager != nil {
		safego.Execute(ctx, a.logger, "ConnectionManagerKillSwitchListener", func() {
			a.connectionManager.StartKillSwitchListener(ctx)
		})
		safego.Execute(ctx, a.logger, "ConnectionManagerAdminKillSwitchListener", func() {
			a.connectionManager.StartAdminKillSwitchListener(ctx)
		})
		safego.Execute(ctx, a.logger, "ConnectionManagerSessionRenewalLoop", func() {
			a.connectionManager.StartSessionRenewalLoop(ctx)
		})
	} else {
		a.logger.Warn(ctx, "ConnectionManager not initialized. Session management features may be impaired.")
	}
	safego.Execute(ctx, a.logger, "SignalListenerAndGracefulShutdown", func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-quit:
			a.logger.Info(context.Background(), "Shutdown signal received, initiating graceful shutdown...", "signal", sig.String())
		case <-ctx.Done():
			a.logger.Info(context.Background(), "Application context cancelled, initiating graceful shutdown...")
		}
		shutdownTimeout := 30 * time.Second
		if a.configProvider != nil && a.configProvider.Get() != nil {
			configApp := a.configProvider.Get().App
			if configApp.ShutdownTimeoutSeconds > 0 {
				shutdownTimeout = time.Duration(configApp.ShutdownTimeoutSeconds) * time.Second
			}
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if a.connectionManager != nil {
			a.connectionManager.StopKillSwitchListener()
			a.connectionManager.StopSessionRenewalLoop()
		}
		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			a.logger.Error(context.Background(), "HTTP server graceful shutdown failed", "error", err.Error())
		}
		a.logger.Info(context.Background(), "HTTP server shut down.")
	})
	a.logger.Info(ctx, fmt.Sprintf("HTTP server listening on port %d", a.configProvider.Get().Server.HTTPPort))
	if err := a.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.logger.Error(ctx, "HTTP server ListenAndServe error", "error", err.Error())
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}
	a.logger.Info(ctx, "Application shut down gracefully or server closed.")
	return nil
}
```

## File: internal/bootstrap/providers.go
```go
package bootstrap
import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
	"github.com/google/wire"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	apphttp "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/http"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/logger"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
	appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats"
	appredis "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/redis"
	wsadapter "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
type TokenGenerationMiddleware func(http.Handler) http.Handler
type AdminAuthMiddleware func(http.Handler) http.Handler
func InitialZapLoggerProvider() (*zap.Logger, func(), error) {
	logger, err := zap.NewProduction()
	if err != nil {
		logger, err = zap.NewDevelopment()
		if err != nil {
			logger = zap.NewExample()
			fmt.Fprintf(os.Stderr, "Failed to create initial zap logger (production and development failed, falling back to example): %v\n", err)
		}
	}
	cleanup := func() {
		if syncErr := logger.Sync(); syncErr != nil {
			fmt.Fprintf(os.Stderr, "Failed to sync initial zap logger: %v\n", syncErr)
		}
	}
	return logger, cleanup, nil
}
type App struct {
	configProvider            config.Provider
	logger                    domain.Logger
	httpServeMux              *http.ServeMux
	httpServer                *http.Server
	generateTokenHandler      http.HandlerFunc
	tokenGenerationMiddleware func(http.Handler) http.Handler
	wsRouter                  *wsadapter.Router
	connectionManager         *application.ConnectionManager
	natsConsumerAdapter       *appnats.ConsumerAdapter
	adminAuthMiddleware       AdminAuthMiddleware
	adminWsHandler            *wsadapter.AdminHandler
}
func NewApp(
	cfgProvider config.Provider,
	appLogger domain.Logger,
	mux *http.ServeMux,
	server *http.Server,
	genTokenHandler http.HandlerFunc,
	tokenGenMiddleware TokenGenerationMiddleware,
	wsRouter *wsadapter.Router,
	connManager *application.ConnectionManager,
	natsAdapter *appnats.ConsumerAdapter,
	adminAuthMid AdminAuthMiddleware,
	adminHandler *wsadapter.AdminHandler,
) (*App, func(), error) {
	app := &App{
		configProvider:            cfgProvider,
		logger:                    appLogger,
		httpServeMux:              mux,
		httpServer:                server,
		generateTokenHandler:      genTokenHandler,
		tokenGenerationMiddleware: tokenGenMiddleware,
		wsRouter:                  wsRouter,
		connectionManager:         connManager,
		natsConsumerAdapter:       natsAdapter,
		adminAuthMiddleware:       adminAuthMid,
		adminWsHandler:            adminHandler,
	}
	cleanup := func() {
		app.logger.Info(context.Background(), "Running app cleanup...")
		if app.connectionManager != nil {
			app.connectionManager.StopKillSwitchListener()
			app.connectionManager.StopSessionRenewalLoop()
		}
	}
	return app, cleanup, nil
}
func ConfigProvider(appCtx context.Context, logger *zap.Logger) (config.Provider, error) {
	return config.NewViperProvider(appCtx, logger)
}
func LoggerProvider(cfgProvider config.Provider) (domain.Logger, error) {
	appCfg := cfgProvider.Get()
	return logger.NewZapAdapter(cfgProvider, appCfg.App.ServiceName)
}
func HTTPServeMuxProvider() *http.ServeMux {
	return http.NewServeMux()
}
func HTTPGracefulServerProvider(cfgProvider config.Provider, mux *http.ServeMux) *http.Server {
	appCfg := cfgProvider.Get()
	readTimeout := 10 * time.Second
	writeTimeout := 10 * time.Second
	idleTimeout := 60 * time.Second
	if appCfg.App.WriteTimeoutSeconds > 0 {
		writeTimeout = time.Duration(appCfg.App.WriteTimeoutSeconds) * time.Second
	}
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", appCfg.Server.HTTPPort),
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
}
func GenerateTokenHandlerProvider(cfgProvider config.Provider, logger domain.Logger) http.HandlerFunc {
	return apphttp.GenerateTokenHandler(cfgProvider, logger)
}
func TokenGenerationAuthMiddlewareProvider(cfgProvider config.Provider, logger domain.Logger) TokenGenerationMiddleware {
	return middleware.TokenGenerationAuthMiddleware(cfgProvider, logger)
}
func AdminAuthMiddlewareProvider(authService *application.AuthService, logger domain.Logger) AdminAuthMiddleware {
	return middleware.AdminAuthMiddleware(authService, logger)
}
func AdminWebsocketHandlerProvider(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter *appnats.ConsumerAdapter) *wsadapter.AdminHandler {
	return wsadapter.NewAdminHandler(logger, cfgProvider, connManager, natsAdapter)
}
func WebsocketHandlerProvider(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter *appnats.ConsumerAdapter) *wsadapter.Handler {
	return wsadapter.NewHandler(logger, cfgProvider, connManager, natsAdapter)
}
func WebsocketRouterProvider(logger domain.Logger, cfgProvider config.Provider, authService *application.AuthService, wsHandler *wsadapter.Handler) *wsadapter.Router {
	return wsadapter.NewRouter(logger, cfgProvider, authService, wsHandler)
}
func AuthServiceProvider(logger domain.Logger, cfgProvider config.Provider, tokenCache domain.TokenCacheStore, adminTokenCache domain.AdminTokenCacheStore) *application.AuthService {
	return application.NewAuthService(logger, cfgProvider, tokenCache, adminTokenCache)
}
func RedisClientProvider(cfgProvider config.Provider, appLogger domain.Logger) (*redis.Client, func(), error) {
	appCfg := cfgProvider.Get()
	client := redis.NewClient(&redis.Options{
		Addr:     appCfg.Redis.Address,
		Password: appCfg.Redis.Password,
		DB:       appCfg.Redis.DB,
	})
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		appLogger.Error(context.Background(), "Failed to connect to Redis", "error", err.Error(), "address", appCfg.Redis.Address)
		return nil, nil, fmt.Errorf("failed to connect to Redis at %s: %w", appCfg.Redis.Address, err)
	}
	cleanup := func() {
		client.Close()
		appLogger.Info(context.Background(), "Redis connection closed")
	}
	appLogger.Info(context.Background(), "Successfully connected to Redis", "address", appCfg.Redis.Address)
	return client, cleanup, nil
}
func SessionLockManagerProvider(redisClient *redis.Client, logger domain.Logger) domain.SessionLockManager {
	return appredis.NewSessionLockManagerAdapter(redisClient, logger)
}
func KillSwitchPubSubAdapterProvider(redisClient *redis.Client, logger domain.Logger) *appredis.KillSwitchPubSubAdapter {
	return appredis.NewKillSwitchPubSubAdapter(redisClient, logger)
}
func ConnectionManagerProvider(
	logger domain.Logger,
	cfgProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPub domain.KillSwitchPublisher,
	killSwitchSub domain.KillSwitchSubscriber,
) *application.ConnectionManager {
	return application.NewConnectionManager(logger, cfgProvider, sessionLocker, killSwitchPub, killSwitchSub)
}
func TokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.TokenCacheStore {
	logger.Warn(context.Background(), "TokenCacheStoreProvider is using a placeholder nil implementation. Actual Redis-backed cache store needs to be implemented.")
	return nil
}
func AdminTokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.AdminTokenCacheStore {
	return appredis.NewAdminTokenCacheAdapter(redisClient, logger)
}
func NatsConsumerAdapterProvider(ctx context.Context, cfgProvider config.Provider, appLogger domain.Logger) (*appnats.ConsumerAdapter, func(), error) {
	return appnats.NewConsumerAdapter(ctx, cfgProvider, appLogger)
}
var ProviderSet = wire.NewSet(
	ConfigProvider,
	LoggerProvider,
	HTTPServeMuxProvider,
	HTTPGracefulServerProvider,
	InitialZapLoggerProvider,
	GenerateTokenHandlerProvider,
	TokenGenerationAuthMiddlewareProvider,
	WebsocketHandlerProvider,
	WebsocketRouterProvider,
	RedisClientProvider,
	SessionLockManagerProvider,
	KillSwitchPubSubAdapterProvider,
	wire.Bind(new(domain.KillSwitchPublisher), new(*appredis.KillSwitchPubSubAdapter)),
	wire.Bind(new(domain.KillSwitchSubscriber), new(*appredis.KillSwitchPubSubAdapter)),
	TokenCacheStoreProvider,
	AuthServiceProvider,
	ConnectionManagerProvider,
	AdminAuthMiddlewareProvider,
	AdminWebsocketHandlerProvider,
	AdminTokenCacheStoreProvider,
	NewApp,
	NatsConsumerAdapterProvider,
)
```
