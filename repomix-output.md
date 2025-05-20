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
    grpc/
      proto/
        dws_message_fwd.proto
      forwarder_adapter.go
      server.go
    http/
      admin_handlers.go
    logger/
      zap_adapter.go
    metrics/
      prometheus_adapter.go
    middleware/
      admin_auth.go
      auth.go
      context.go
    nats/
      consumer.go
    redis/
      admin_token_cache_adapter.go
      kill_switch_pubsub.go
      route_registry.go
      session_lock_manager.go
      token_cache_adapter.go
    websocket/
      admin_handler.go
      conn.go
      handler.go
      router.go
  application/
    auth_service.go
    connection_manager.go
    connection_registry.go
    grpc_handler.go
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
    forwarder.go
    logger.go
    nats_payloads.go
    nats.go
    route_registry.go
    session.go
    websocket_protocol.go
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

## File: internal/adapters/grpc/proto/dws_message_fwd.proto
```protobuf
syntax = "proto3";

package dws_message_fwd;

import "google/protobuf/timestamp.proto";
import "google/protobuf/struct.proto";

option go_package = "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc/proto;dws_message_fwd";

service MessageForwardingService {
  rpc PushEvent(PushEventRequest) returns (PushEventResponse);
}

message EnrichedEventPayloadMessage {
  string event_id = 1;
  string event_type = 2;
  google.protobuf.Timestamp timestamp = 3;
  string source = 4;
  google.protobuf.Struct data = 5; // For arbitrary JSON-like data
}

message PushEventRequest {
  EnrichedEventPayloadMessage payload = 1;
  string target_company_id = 2; // For routing/logging on recipient
  string target_agent_id = 3;
  string target_chat_id = 4;
  string source_pod_id = 5; // Added to track source for metrics
}

message PushEventResponse {
  bool success = 1;
  string message = 2; // Optional: error message or status
}
```

## File: internal/adapters/grpc/forwarder_adapter.go
```go
package grpc
import (
	"context"
	"fmt"
	"sync"
	"time"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	pb "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc/proto"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)
const (
	defaultGRPCPoolIdleTimeout             = 300 * time.Second
	defaultGRPCPoolHealthCheckInterval     = 60 * time.Second
	defaultGRPCCircuitBreakerFailThreshold = 5
	defaultGRPCCircuitBreakerOpenDuration  = 30 * time.Second
)
type pooledConnection struct {
	conn         *grpc.ClientConn
	lastUsedTime time.Time
	mu           sync.Mutex
}
type circuitBreakerState struct {
	failures    int
	lastFailure time.Time
	openUntil   time.Time
	targetPodID string
}
type ForwarderAdapter struct {
	logger              domain.Logger
	configProvider      config.Provider
	grpcClientPool      *sync.Map
	circuitBreakers     *sync.Map
	appCtx              context.Context
	appCancel           context.CancelFunc
	idleTimeout         time.Duration
	healthCheckInterval time.Duration
	failThreshold       int
	openDuration        time.Duration
}
func NewForwarderAdapter(appCtx context.Context, logger domain.Logger, configProvider config.Provider) *ForwarderAdapter {
	appCfg := configProvider.Get().App
	idleTimeout := defaultGRPCPoolIdleTimeout
	if appCfg.GrpcPoolIdleTimeoutSeconds > 0 {
		idleTimeout = time.Duration(appCfg.GrpcPoolIdleTimeoutSeconds) * time.Second
	}
	healthCheckInterval := defaultGRPCPoolHealthCheckInterval
	if appCfg.GrpcPoolHealthCheckIntervalSeconds > 0 {
		healthCheckInterval = time.Duration(appCfg.GrpcPoolHealthCheckIntervalSeconds) * time.Second
	}
	failThreshold := defaultGRPCCircuitBreakerFailThreshold
	if appCfg.GrpcCircuitBreakerFailThreshold > 0 {
		failThreshold = appCfg.GrpcCircuitBreakerFailThreshold
	}
	openDuration := defaultGRPCCircuitBreakerOpenDuration
	if appCfg.GrpcCircuitBreakerOpenDurationSeconds > 0 {
		openDuration = time.Duration(appCfg.GrpcCircuitBreakerOpenDurationSeconds) * time.Second
	}
	adapterCtx, adapterCancel := context.WithCancel(appCtx)
	fa := &ForwarderAdapter{
		logger:              logger,
		configProvider:      configProvider,
		grpcClientPool:      &sync.Map{},
		circuitBreakers:     &sync.Map{},
		appCtx:              adapterCtx,
		appCancel:           adapterCancel,
		idleTimeout:         idleTimeout,
		healthCheckInterval: healthCheckInterval,
		failThreshold:       failThreshold,
		openDuration:        openDuration,
	}
	fa.startCleanupRoutine()
	return fa
}
func (fa *ForwarderAdapter) getCircuitBreaker(targetPodID string) *circuitBreakerState {
	cbVal, _ := fa.circuitBreakers.LoadOrStore(targetPodID, &circuitBreakerState{targetPodID: targetPodID})
	return cbVal.(*circuitBreakerState)
}
func (fa *ForwarderAdapter) isCircuitOpen(targetPodID string) bool {
	cb := fa.getCircuitBreaker(targetPodID)
	if cb.openUntil.IsZero() || time.Now().After(cb.openUntil) {
		return false
	}
	return true
}
func (fa *ForwarderAdapter) recordFailure(targetPodID string) {
	cb := fa.getCircuitBreaker(targetPodID)
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= fa.failThreshold {
		cb.openUntil = time.Now().Add(fa.openDuration)
		fa.logger.Warn(fa.appCtx, "Circuit breaker tripped for target pod", "target_pod_id", targetPodID, "open_until", cb.openUntil)
		metrics.IncrementGrpcCircuitBreakerTripped(targetPodID)
		if connVal, okPool := fa.grpcClientPool.Load(targetPodID); okPool {
			pc := connVal.(*pooledConnection)
			pc.mu.Lock()
			if pc.conn != nil {
				pc.conn.Close()
				pc.conn = nil
				metrics.IncrementGrpcPoolConnectionsClosed("circuit_trip")
				fa.logger.Info(fa.appCtx, "Closed gRPC connection due to circuit breaker trip", "target_pod_id", targetPodID)
			}
			pc.mu.Unlock()
			fa.grpcClientPool.Delete(targetPodID)
		}
	}
}
func (fa *ForwarderAdapter) recordSuccess(targetPodID string) {
	cb := fa.getCircuitBreaker(targetPodID)
	cb.failures = 0
	cb.openUntil = time.Time{}
}
func (fa *ForwarderAdapter) getConnection(ctx context.Context, targetPodAddress string) (*grpc.ClientConn, error) {
	if fa.isCircuitOpen(targetPodAddress) {
		fa.logger.Warn(ctx, "Circuit breaker is open for target, refusing connection attempt", "target_pod_address", targetPodAddress)
		return nil, fmt.Errorf("circuit breaker open for %s", targetPodAddress)
	}
	connVal, okPool := fa.grpcClientPool.Load(targetPodAddress)
	if okPool {
		pc := connVal.(*pooledConnection)
		pc.mu.Lock()
		defer pc.mu.Unlock()
		if pc.conn != nil {
			state := pc.conn.GetState()
			if state == connectivity.Ready || state == connectivity.Idle {
				pc.lastUsedTime = time.Now()
				fa.logger.Debug(ctx, "Reusing healthy gRPC connection from pool", "target_address", targetPodAddress, "state", state.String())
				return pc.conn, nil
			}
			fa.logger.Warn(ctx, "Pooled gRPC connection is not healthy, closing and removing", "target_address", targetPodAddress, "state", state.String())
			pc.conn.Close()
			pc.conn = nil
			metrics.IncrementGrpcPoolConnectionsClosed("health_fail")
		}
	}
	fa.logger.Info(ctx, "Creating new gRPC client connection", "target_address", targetPodAddress)
	connOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	newlyCreatedConn, errClient := grpc.NewClient(targetPodAddress, connOpts...)
	if errClient != nil {
		fa.logger.Error(ctx, "Failed to establish new gRPC connection", "target_pod_address", targetPodAddress, "error", errClient.Error())
		metrics.IncrementGrpcPoolConnectionErrors(targetPodAddress)
		fa.recordFailure(targetPodAddress)
		return nil, errClient
	}
	pc := &pooledConnection{
		conn:         newlyCreatedConn,
		lastUsedTime: time.Now(),
	}
	fa.grpcClientPool.Store(targetPodAddress, pc)
	metrics.IncrementGrpcPoolConnectionsCreated()
	metrics.SetGrpcPoolSize(float64(getSyncMapLength(fa.grpcClientPool)))
	return newlyCreatedConn, nil
}
func (fa *ForwarderAdapter) ForwardEvent(ctx context.Context, targetPodAddress string, event *domain.EnrichedEventPayload, targetCompanyID, targetAgentID, targetChatID, sourcePodID string) error {
	fa.logger.Info(ctx, "Attempting to forward message via gRPC", "target_address", targetPodAddress, "event_id", event.EventID)
	grpcConn, errClient := fa.getConnection(ctx, targetPodAddress)
	if errClient != nil {
		return fmt.Errorf("failed to get gRPC connection for %s: %w", targetPodAddress, errClient)
	}
	client := pb.NewMessageForwardingServiceClient(grpcConn)
	protoData, errProtoStruct := structpb.NewStruct(event.Data.(map[string]interface{}))
	if errProtoStruct != nil {
		fa.logger.Error(ctx, "Failed to convert event.Data to proto.Struct for gRPC", "error", errProtoStruct.Error())
		return errProtoStruct
	}
	grpcRequest := &pb.PushEventRequest{
		Payload: &pb.EnrichedEventPayloadMessage{
			EventId:   event.EventID,
			EventType: event.EventType,
			Timestamp: timestamppb.New(event.Timestamp),
			Source:    event.Source,
			Data:      protoData,
		},
		TargetCompanyId: targetCompanyID,
		TargetAgentId:   targetAgentID,
		TargetChatId:    targetChatID,
		SourcePodId:     sourcePodID,
	}
	mdOut := metadata.New(nil)
	if reqID, okCtxVal := ctx.Value(contextkeys.RequestIDKey).(string); okCtxVal && reqID != "" {
		mdOut.Set(string(contextkeys.RequestIDKey), reqID)
	}
	pushCtxWithMetadata := metadata.NewOutgoingContext(ctx, mdOut)
	grpcClientTimeoutSeconds := fa.configProvider.Get().App.GRPCCLientForwardTimeoutSeconds
	grpcClientTimeout := 5 * time.Second // Default timeout
	if grpcClientTimeoutSeconds > 0 {
		grpcClientTimeout = time.Duration(grpcClientTimeoutSeconds) * time.Second
	}
	var finalErr error
	for i := 0; i < 2; i++ { // 0: initial attempt, 1: retry attempt
		pushCtx, pushCancel := context.WithTimeout(pushCtxWithMetadata, grpcClientTimeout)
		resp, errPush := client.PushEvent(pushCtx, grpcRequest)
		pushCancel()
		if errPush == nil {
			if resp != nil && resp.Success {
				fa.logger.Info(ctx, "Successfully forwarded message via gRPC", "target_pod_address", targetPodAddress, "event_id", event.EventID, "attempt", i)
				metrics.IncrementGrpcMessagesSent(targetPodAddress)
				fa.recordSuccess(targetPodAddress)
				if i > 0 {
					metrics.IncrementGrpcForwardRetrySuccess(targetPodAddress)
				}
				if connVal, okPool := fa.grpcClientPool.Load(targetPodAddress); okPool {
					connVal.(*pooledConnection).lastUsedTime = time.Now()
				}
				return nil
			}
			finalErr = fmt.Errorf("gRPC PushEvent to %s was not successful: %s (attempt %d)", targetPodAddress, resp.Message, i)
			fa.logger.Warn(ctx, finalErr.Error())
			break
		}
		finalErr = errPush
		metrics.IncrementGrpcPoolConnectionErrors(targetPodAddress)
		fa.recordFailure(targetPodAddress)
		st, ok := status.FromError(errPush)
		if ok && (st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded) {
			fa.logger.Warn(ctx, "gRPC PushEvent to owner pod failed with retryable error", "target_pod_address", targetPodAddress, "error", errPush.Error(), "grpc_code", st.Code().String(), "attempt", i)
			if i == 0 {
				metrics.IncrementGrpcForwardRetryAttempts(targetPodAddress)
				time.Sleep(200 * time.Millisecond)
				grpcConn, errClient = fa.getConnection(ctx, targetPodAddress)
				if errClient != nil {
					return fmt.Errorf("failed to get gRPC connection for retry to %s: %w", targetPodAddress, errClient)
				}
				client = pb.NewMessageForwardingServiceClient(grpcConn)
				continue
			}
		} else {
			fa.logger.Error(ctx, "gRPC PushEvent to owner pod failed with non-retryable error", "target_pod_address", targetPodAddress, "error", errPush.Error(), "attempt", i)
			break
		}
	}
	if finalErr != nil {
		metrics.IncrementGrpcForwardRetryFailure(targetPodAddress)
		return finalErr
	}
	return nil
}
func (fa *ForwarderAdapter) startCleanupRoutine() {
	ticker := time.NewTicker(fa.healthCheckInterval)
	safego.Execute(fa.appCtx, fa.logger, "GRPCPoolCleanupRoutine", func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fa.cleanupIdleConnections()
			case <-fa.appCtx.Done():
				fa.logger.Info(fa.appCtx, "gRPC pool cleanup routine stopping.")
				fa.closeAllConnections()
				return
			}
		}
	})
}
func (fa *ForwarderAdapter) cleanupIdleConnections() {
	now := time.Now()
	cleanedCount := 0
	fa.grpcClientPool.Range(func(key, value interface{}) bool {
		targetPodAddress := key.(string)
		pc := value.(*pooledConnection)
		pc.mu.Lock()
		if pc.conn != nil && now.Sub(pc.lastUsedTime) > fa.idleTimeout {
			fa.logger.Info(fa.appCtx, "Closing idle gRPC connection", "target_address", targetPodAddress, "idle_duration_seconds", now.Sub(pc.lastUsedTime).Seconds())
			pc.conn.Close()
			pc.conn = nil
			metrics.IncrementGrpcPoolConnectionsClosed("idle")
			cleanedCount++
			fa.grpcClientPool.Delete(targetPodAddress)
		}
		pc.mu.Unlock()
		return true
	})
	if cleanedCount > 0 {
		fa.logger.Info(fa.appCtx, "Cleaned up idle gRPC connections", "count", cleanedCount)
	}
	metrics.SetGrpcPoolSize(float64(getSyncMapLength(fa.grpcClientPool)))
}
func (fa *ForwarderAdapter) closeAllConnections() {
	fa.logger.Info(fa.appCtx, "Closing all gRPC client connections in pool...")
	closedCount := 0
	fa.grpcClientPool.Range(func(key, value interface{}) bool {
		targetPodAddress := key.(string)
		pc := value.(*pooledConnection)
		pc.mu.Lock()
		if pc.conn != nil {
			pc.conn.Close()
			pc.conn = nil
			metrics.IncrementGrpcPoolConnectionsClosed("shutdown")
			closedCount++
		}
		pc.mu.Unlock()
		fa.grpcClientPool.Delete(targetPodAddress)
		return true
	})
	fa.logger.Info(fa.appCtx, "All gRPC client connections closed.", "count", closedCount)
	metrics.SetGrpcPoolSize(0)
}
func getSyncMapLength(m *sync.Map) int {
	length := 0
	m.Range(func(_, _ interface{}) bool {
		length++
		return true
	})
	return length
}
func (fa *ForwarderAdapter) Stop() {
	fa.logger.Info(fa.appCtx, "Stopping ForwarderAdapter...")
	fa.appCancel()
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

## File: internal/adapters/middleware/context.go
```go
package middleware
import (
	"context"
	"net/http"
	"github.com/google/uuid"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
)
const XRequestIDHeader = "X-Request-ID"
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(XRequestIDHeader)
		if requestID == "" {
			requestID = uuid.NewString()
		}
		ctx := context.WithValue(r.Context(), contextkeys.RequestIDKey, requestID)
		w.Header().Set(XRequestIDHeader, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

## File: internal/adapters/redis/route_registry.go
```go
package redis
import (
	"context"
	"errors"
	"fmt"
	"time"
	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)
var ErrNoOwningPod = errors.New("no owning pod found for the route")
type RouteRegistryAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
}
func NewRouteRegistryAdapter(redisClient *redis.Client, logger domain.Logger) *RouteRegistryAdapter {
	if redisClient == nil {
		panic("redisClient cannot be nil in NewRouteRegistryAdapter")
	}
	if logger == nil {
		panic("logger cannot be nil in NewRouteRegistryAdapter")
	}
	return &RouteRegistryAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}
func (a *RouteRegistryAdapter) RegisterChatRoute(ctx context.Context, companyID, agentID, podID string, ttl time.Duration) error {
	key := rediskeys.RouteKeyChats(companyID, agentID)
	a.logger.Debug(ctx, "Registering chat route", "key", key, "podID", podID, "ttl", ttl.String())
	pipe := a.redisClient.Pipeline()
	pipe.SAdd(ctx, key, podID)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		a.logger.Error(ctx, "Failed to register chat route", "key", key, "podID", podID, "error", err.Error())
		return fmt.Errorf("redis SADD/EXPIRE for chat route key '%s' failed: %w", key, err)
	}
	return nil
}
func (a *RouteRegistryAdapter) UnregisterChatRoute(ctx context.Context, companyID, agentID, podID string) error {
	key := rediskeys.RouteKeyChats(companyID, agentID)
	a.logger.Debug(ctx, "Unregistering chat route", "key", key, "podID", podID)
	err := a.redisClient.SRem(ctx, key, podID).Err()
	if err != nil {
		a.logger.Error(ctx, "Failed to unregister chat route", "key", key, "podID", podID, "error", err.Error())
		return fmt.Errorf("redis SREM for chat route key '%s' failed: %w", key, err)
	}
	return nil
}
func (a *RouteRegistryAdapter) RegisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string, ttl time.Duration) error {
	key := rediskeys.RouteKeyMessages(companyID, agentID, chatID)
	a.logger.Debug(ctx, "Registering message route", "key", key, "podID", podID, "ttl", ttl.String())
	pipe := a.redisClient.Pipeline()
	pipe.SAdd(ctx, key, podID)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		a.logger.Error(ctx, "Failed to register message route", "key", key, "podID", podID, "error", err.Error())
		return fmt.Errorf("redis SADD/EXPIRE for message route key '%s' failed: %w", key, err)
	}
	return nil
}
func (a *RouteRegistryAdapter) UnregisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string) error {
	key := rediskeys.RouteKeyMessages(companyID, agentID, chatID)
	a.logger.Debug(ctx, "Unregistering message route", "key", key, "podID", podID)
	err := a.redisClient.SRem(ctx, key, podID).Err()
	if err != nil {
		a.logger.Error(ctx, "Failed to unregister message route", "key", key, "podID", podID, "error", err.Error())
		return fmt.Errorf("redis SREM for message route key '%s' failed: %w", key, err)
	}
	return nil
}
func (a *RouteRegistryAdapter) GetOwningPodForMessageRoute(ctx context.Context, companyID, agentID, chatID string) (string, error) {
	key := rediskeys.RouteKeyMessages(companyID, agentID, chatID)
	members, err := a.redisClient.SMembers(ctx, key).Result()
	if err != nil {
		a.logger.Error(ctx, "Failed to get members for message route", "key", key, "error", err.Error())
		return "", fmt.Errorf("redis SMEMBERS for message route key '%s' failed: %w", key, err)
	}
	if len(members) == 0 {
		a.logger.Debug(ctx, "No owning pod found for message route", "key", key)
		return "", ErrNoOwningPod
	}
	if len(members) > 1 {
		a.logger.Warn(ctx, "Multiple owning pods found for message route, returning first", "key", key, "pods", members)
	}
	return members[0], nil
}
func (a *RouteRegistryAdapter) GetOwningPodsForChatRoute(ctx context.Context, companyID, agentID string) ([]string, error) {
	key := rediskeys.RouteKeyChats(companyID, agentID)
	members, err := a.redisClient.SMembers(ctx, key).Result()
	if err != nil {
		a.logger.Error(ctx, "Failed to get members for chat route", "key", key, "error", err.Error())
		return nil, fmt.Errorf("redis SMEMBERS for chat route key '%s' failed: %w", key, err)
	}
	if len(members) == 0 {
		a.logger.Debug(ctx, "No owning pods found for chat route", "key", key)
	}
	return members, nil
}
func (a *RouteRegistryAdapter) RefreshRouteTTL(ctx context.Context, routeKey, podID string, ttl time.Duration) (bool, error) {
	script := `
        if redis.call("sismember", KEYS[1], ARGV[1]) == 1 then
            return redis.call("expire", KEYS[1], ARGV[2])
        else
            return 0
        end
    `
	ttlSeconds := int64(ttl.Seconds())
	result, err := a.redisClient.Eval(ctx, script, []string{routeKey}, podID, ttlSeconds).Int64()
	if err != nil && !errors.Is(err, redis.Nil) {
		a.logger.Error(ctx, "Redis EVAL (RefreshRouteTTL script) failed", "key", routeKey, "podID", podID, "error", err.Error())
		return false, fmt.Errorf("redis EVAL for RefreshRouteTTL on key '%s' failed: %w", routeKey, err)
	}
	refreshed := result == 1
	a.logger.Debug(ctx, "Redis RefreshRouteTTL result", "key", routeKey, "podID", podID, "ttl_seconds", ttlSeconds, "refreshed_by_script", refreshed, "script_result_val", result)
	return refreshed, nil
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

## File: internal/adapters/redis/token_cache_adapter.go
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
type TokenCacheAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
}
func NewTokenCacheAdapter(redisClient *redis.Client, logger domain.Logger) *TokenCacheAdapter {
	if redisClient == nil {
		panic("redisClient cannot be nil in NewTokenCacheAdapter")
	}
	if logger == nil {
		panic("logger cannot be nil in NewTokenCacheAdapter")
	}
	return &TokenCacheAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}
func (a *TokenCacheAdapter) Get(ctx context.Context, key string) (*domain.AuthenticatedUserContext, error) {
	val, err := a.redisClient.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		a.logger.Debug(ctx, "Company token cache miss", "key", key)
		return nil, application.ErrCacheMiss
	}
	if err != nil {
		a.logger.Error(ctx, "Failed to get company token from Redis cache", "key", key, "error", err.Error())
		return nil, fmt.Errorf("redis GET for company token key '%s' failed: %w", key, err)
	}
	var userCtx domain.AuthenticatedUserContext
	if err = json.Unmarshal([]byte(val), &userCtx); err != nil {
		a.logger.Error(ctx, "Failed to unmarshal cached company token data", "key", key, "error", err.Error())
		return nil, fmt.Errorf("failed to unmarshal company token data for key '%s': %w", key, err)
	}
	a.logger.Debug(ctx, "Company token cache hit", "key", key, "user_id", userCtx.UserID)
	return &userCtx, nil
}
func (a *TokenCacheAdapter) Set(ctx context.Context, key string, value *domain.AuthenticatedUserContext, ttl time.Duration) error {
	payloadBytes, err := json.Marshal(value)
	if err != nil {
		a.logger.Error(ctx, "Failed to marshal company token for caching", "key", key, "user_id", value.UserID, "error", err.Error())
		return fmt.Errorf("failed to marshal company token for key '%s': %w", key, err)
	}
	if err = a.redisClient.Set(ctx, key, string(payloadBytes), ttl).Err(); err != nil {
		a.logger.Error(ctx, "Failed to set company token in Redis cache", "key", key, "user_id", value.UserID, "error", err.Error())
		return fmt.Errorf("redis SET for company token key '%s' failed: %w", key, err)
	}
	a.logger.Debug(ctx, "Successfully cached company token", "key", key, "user_id", value.UserID, "ttl", ttl.String())
	return nil
}
```

## File: internal/application/grpc_handler.go
```go
package application
import (
	"context"
	"fmt"
	"strings"
	pb "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc/proto"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"google.golang.org/grpc/metadata"
)
type GRPCMessageHandler struct {
	pb.UnimplementedMessageForwardingServiceServer
	logger      domain.Logger
	connManager *ConnectionManager
}
func NewGRPCMessageHandler(logger domain.Logger, connManager *ConnectionManager) *GRPCMessageHandler {
	return &GRPCMessageHandler{
		logger:      logger,
		connManager: connManager,
	}
}
func (h *GRPCMessageHandler) PushEvent(ctx context.Context, req *pb.PushEventRequest) (*pb.PushEventResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	logCtx := ctx
	if ok {
		if reqIDValues := md.Get(string(contextkeys.RequestIDKey)); len(reqIDValues) > 0 {
			logCtx = context.WithValue(ctx, contextkeys.RequestIDKey, reqIDValues[0])
			h.logger.Debug(logCtx, "Extracted request_id from gRPC metadata", "request_id", reqIDValues[0])
		} else {
			h.logger.Debug(logCtx, "No request_id found in gRPC metadata")
		}
	} else {
		h.logger.Debug(logCtx, "No gRPC metadata found in incoming context")
	}
	metrics.IncrementGrpcMessagesReceived(req.SourcePodId)
	h.logger.Info(logCtx, "gRPC PushEvent received",
		"target_company_id", req.TargetCompanyId,
		"target_agent_id", req.TargetAgentId,
		"target_chat_id", req.TargetChatId,
		"source_event_id", req.Payload.EventId,
	)
	if req.Payload == nil {
		h.logger.Warn(logCtx, "gRPC PushEvent received nil payload")
		return &pb.PushEventResponse{Success: false, Message: "Nil payload received"}, fmt.Errorf("nil payload")
	}
	sessionKeyPrefix := fmt.Sprintf("session:%s:%s:", req.TargetCompanyId, req.TargetAgentId)
	var targetConn domain.ManagedConnection
	found := false
	h.connManager.activeConnections.Range(func(key, value interface{}) bool {
		sKey, okKey := key.(string)
		conn, okConn := value.(domain.ManagedConnection)
		if !okKey || !okConn {
			return true
		}
		if strings.HasPrefix(sKey, sessionKeyPrefix) {
			if conn.GetCurrentChatID() == req.TargetChatId {
				targetConn = conn
				found = true
				return false
			}
		}
		return true
	})
	if !found || targetConn == nil {
		h.logger.Warn(logCtx, "gRPC PushEvent: No active local WebSocket connection found for target chat_id on this pod",
			"target_company_id", req.TargetCompanyId, "target_agent_id", req.TargetAgentId, "target_chat_id", req.TargetChatId)
		return &pb.PushEventResponse{Success: false, Message: "No active local connection for chat_id"}, nil
	}
	var mapData map[string]interface{}
	if req.Payload.Data != nil {
		mapData = req.Payload.Data.AsMap()
	}
	domainPayload := domain.EnrichedEventPayload{
		EventID:   req.Payload.EventId,
		EventType: req.Payload.EventType,
		Timestamp: req.Payload.Timestamp.AsTime(),
		Source:    req.Payload.Source,
		Data:      mapData,
	}
	wsMessage := domain.NewEventMessage(domainPayload)
	if err := targetConn.WriteJSON(wsMessage); err != nil {
		h.logger.Error(targetConn.Context(), "gRPC PushEvent: Failed to write message to local WebSocket connection",
			"target_company_id", req.TargetCompanyId, "target_agent_id", req.TargetAgentId, "target_chat_id", req.TargetChatId,
			"error", err.Error(),
		)
		return &pb.PushEventResponse{Success: false, Message: "Failed to write to local WebSocket"}, nil
	}
	h.logger.Info(targetConn.Context(), "gRPC PushEvent: Successfully delivered message to local WebSocket connection",
		"target_company_id", req.TargetCompanyId, "target_agent_id", req.TargetAgentId, "target_chat_id", req.TargetChatId,
	)
	return &pb.PushEventResponse{Success: true, Message: "Event delivered to local WebSocket"}, nil
}
```

## File: internal/domain/forwarder.go
```go
package domain
import (
	"context"
)
type MessageForwarder interface {
	ForwardEvent(ctx context.Context, targetPodAddress string, event *EnrichedEventPayload, targetCompanyID, targetAgentID, targetChatID, sourcePodID string) error
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

## File: internal/domain/nats.go
```go
package domain
import (
	"context"
	"github.com/nats-io/nats.go"
)
type NatsMessageSubscription interface {
	Drain() error
	IsValid() bool
	Subject() string
}
type NatsMessageHandler func(msg *nats.Msg)
type NatsConsumer interface {
	SubscribeToChats(ctx context.Context, companyID, agentID string, handler NatsMessageHandler) (NatsMessageSubscription, error)
	SubscribeToChatMessages(ctx context.Context, companyID, agentID, chatID string, handler NatsMessageHandler) (NatsMessageSubscription, error)
	SubscribeToAgentEvents(ctx context.Context, companyIDPattern, agentIDPattern string, handler NatsMessageHandler) (NatsMessageSubscription, error)
	NatsConn() *nats.Conn
	Close()
}
```

## File: internal/domain/route_registry.go
```go
package domain
import (
	"context"
	"time"
)
type RouteRegistry interface {
	RegisterChatRoute(ctx context.Context, companyID, agentID, podID string, ttl time.Duration) error
	UnregisterChatRoute(ctx context.Context, companyID, agentID, podID string) error
	RegisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string, ttl time.Duration) error
	UnregisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string) error
	GetOwningPodForMessageRoute(ctx context.Context, companyID, agentID, chatID string) (string, error)
	GetOwningPodsForChatRoute(ctx context.Context, companyID, agentID string) ([]string, error)
	RefreshRouteTTL(ctx context.Context, routeKey, podID string, ttl time.Duration) (bool, error)
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

## File: internal/domain/websocket_protocol.go
```go
package domain
import (
	"github.com/coder/websocket"
)
const (
	MessageTypeReady      = "ready"
	MessageTypeEvent      = "event"
	MessageTypeError      = "error"
	MessageTypeSelectChat = "select_chat"
	StatusGoingAway websocket.StatusCode = 1001
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
func NewErrorMessage(errResp ErrorResponse) BaseMessage {
	return BaseMessage{
		Type:    MessageTypeError,
		Payload: errResp,
	}
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

## File: internal/adapters/grpc/server.go
```go
package grpc
import (
	"context"
	"fmt"
	"net"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	pb "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc/proto"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)
type Server struct {
	gsrv        *grpc.Server
	logger      domain.Logger
	cfgProvider config.Provider
	appCtx      context.Context
	cancelCtx   context.CancelFunc
}
func NewServer(appCtx context.Context, logger domain.Logger, cfgProvider config.Provider, grpcHandler *application.GRPCMessageHandler) (*Server, error) {
	opts := []grpc.ServerOption{}
	gsrv := grpc.NewServer(opts...)
	pb.RegisterMessageForwardingServiceServer(gsrv, grpcHandler)
	if cfgProvider.Get().Server.EnableReflection {
		reflection.Register(gsrv)
		logger.Info(appCtx, "gRPC reflection enabled.")
	} else {
		logger.Info(appCtx, "gRPC reflection disabled.")
	}
	serverLifecycleCtx, serverLifecycleCancel := context.WithCancel(appCtx)
	return &Server{
		gsrv:        gsrv,
		logger:      logger,
		cfgProvider: cfgProvider,
		appCtx:      serverLifecycleCtx,
		cancelCtx:   serverLifecycleCancel,
	}, nil
}
func (s *Server) Start() error {
	grpcPort := s.cfgProvider.Get().Server.GRPCPort
	if grpcPort == 0 {
		s.logger.Warn(s.appCtx, "gRPC port is not configured or is 0. gRPC server will not start.")
		return fmt.Errorf("gRPC port not configured")
	}
	addr := fmt.Sprintf(":%d", grpcPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error(s.appCtx, "Failed to listen for gRPC", "address", addr, "error", err)
		return fmt.Errorf("failed to listen for gRPC on %s: %w", addr, err)
	}
	s.logger.Info(s.appCtx, "gRPC server starting", "address", addr)
	safego.Execute(s.appCtx, s.logger, "GRPCServerServe", func() {
		if err := s.gsrv.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			s.logger.Error(s.appCtx, "gRPC server failed to serve", "error", err)
		}
		s.logger.Info(s.appCtx, "gRPC server Serve() returned. Ensuring context is cancelled.")
		s.cancelCtx()
	})
	safego.Execute(s.appCtx, s.logger, "GRPCServerContextWatcher", func() {
		<-s.appCtx.Done()
		s.logger.Info(context.Background(), "gRPC server context done (e.g. from app shutdown), initiating graceful stop...")
		s.gsrv.GracefulStop()
		s.logger.Info(context.Background(), "gRPC server gracefully stopped after context cancellation.")
	})
	return nil
}
func (s *Server) GracefulStop() {
	s.logger.Info(s.appCtx, "GracefulStop called for gRPC server. Cancelling its lifecycle context to trigger stop.")
	s.cancelCtx()
}
```

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
type GenerateAdminTokenRequest struct {
	AdminID              string `json:"admin_id"`
	ExpiresInSeconds     int    `json:"expires_in_seconds"`
	SubscribedCompanyID  string `json:"subscribed_company_id,omitempty"`
	SubscribedAgentID    string `json:"subscribed_agent_id,omitempty"`
	CompanyIDRestriction string `json:"company_id_restriction,omitempty"`
}
type GenerateAdminTokenResponse struct {
	Token string `json:"token"`
}
func GenerateAdminTokenHandler(cfgProvider config.Provider, logger domain.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			logger.Warn(r.Context(), "Invalid method for /admin/generate-token", "method", r.Method)
			domain.NewErrorResponse(domain.ErrMethodNotAllowed, "Method not allowed", "Only POST method is allowed.").WriteJSON(w, http.StatusMethodNotAllowed)
			return
		}
		var reqPayload GenerateAdminTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
			logger.Warn(r.Context(), "Failed to decode /admin/generate-token payload", "error", err.Error())
			domain.NewErrorResponse(domain.ErrBadRequest, "Invalid request payload", err.Error()).WriteJSON(w, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		if reqPayload.AdminID == "" || reqPayload.ExpiresInSeconds <= 0 {
			logger.Warn(r.Context(), "Invalid payload for /admin/generate-token", "payload", reqPayload)
			domain.NewErrorResponse(domain.ErrBadRequest, "Invalid payload", "admin_id and positive expires_in_seconds are required.").WriteJSON(w, http.StatusBadRequest)
			return
		}
		appAuthCfg := cfgProvider.Get().Auth
		if appAuthCfg.AdminTokenAESKey == "" {
			logger.Error(r.Context(), "AdminTokenAESKey not configured for /admin/generate-token")
			domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Admin token encryption key not configured.").WriteJSON(w, http.StatusInternalServerError)
			return
		}
		adminTokenContext := domain.AdminUserContext{
			AdminID:              reqPayload.AdminID,
			ExpiresAt:            time.Now().Add(time.Duration(reqPayload.ExpiresInSeconds) * time.Second),
			SubscribedCompanyID:  reqPayload.SubscribedCompanyID,
			SubscribedAgentID:    reqPayload.SubscribedAgentID,
			CompanyIDRestriction: reqPayload.CompanyIDRestriction,
		}
		plaintextTokenPayload, err := json.Marshal(adminTokenContext)
		if err != nil {
			logger.Error(r.Context(), "Failed to marshal admin token context for /admin/generate-token", "error", err.Error())
			domain.NewErrorResponse(domain.ErrInternal, "Failed to create admin token", "Internal error during token generation.").WriteJSON(w, http.StatusInternalServerError)
			return
		}
		encryptedToken, err := crypto.EncryptAESGCM(appAuthCfg.AdminTokenAESKey, plaintextTokenPayload)
		if err != nil {
			logger.Error(r.Context(), "Failed to encrypt admin token for /admin/generate-token", "error", err.Error())
			domain.NewErrorResponse(domain.ErrInternal, "Failed to create admin token", "Internal error during token encryption.").WriteJSON(w, http.StatusInternalServerError)
			return
		}
		resp := GenerateAdminTokenResponse{Token: encryptedToken}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error(r.Context(), "Failed to encode /admin/generate-token response", "error", err.Error())
		}
	}
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
	ConnectionsTotalCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dws_connections_total",
			Help: "Total WebSocket connections initiated (successful handshakes).",
		},
	)
	ConnectionDurationHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dws_connection_duration_seconds",
			Help:    "Duration of WebSocket connections.",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 15),
		},
	)
	MessagesReceivedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_messages_received_total",
			Help: "Total messages received from clients, partitioned by message type.",
		},
		[]string{"message_type"},
	)
	MessagesSentCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_messages_sent_total",
			Help: "Total messages sent to clients, partitioned by message type.",
		},
		[]string{"message_type"},
	)
	AuthSuccessTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_auth_success_total",
			Help: "Successful token validations.",
		},
		[]string{"token_type"},
	)
	AuthFailureTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_auth_failure_total",
			Help: "Failed token validations.",
		},
		[]string{"token_type", "reason"},
	)
	SessionConflictsTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_session_conflicts_total",
			Help: "Number of session conflicts detected.",
		},
		[]string{"user_type"},
	)
	NatsMessagesReceivedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_nats_messages_received_total",
			Help: "Messages received from NATS, partitioned by NATS subject.",
		},
		[]string{"nats_subject"},
	)
	GrpcMessagesSentCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_messages_sent_total",
			Help: "Messages forwarded via gRPC, partitioned by target pod ID.",
		},
		[]string{"target_pod_id"},
	)
	GrpcMessagesReceivedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_messages_received_total",
			Help: "Messages received via gRPC, partitioned by source pod ID.",
		},
		[]string{"source_pod_id"},
	)
	GrpcForwardRetryAttemptsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_forward_retry_attempts_total",
			Help: "Total gRPC message forwarding retry attempts.",
		},
		[]string{"target_pod_id"},
	)
	GrpcForwardRetrySuccessCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_forward_retry_success_total",
			Help: "Total successful gRPC message forwarding retries.",
		},
		[]string{"target_pod_id"},
	)
	GrpcForwardRetryFailureCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_forward_retry_failure_total",
			Help: "Total failed gRPC message forwarding retries.",
		},
		[]string{"target_pod_id"},
	)
	SessionLockAttemptsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_session_lock_attempts_total",
			Help: "Total session lock acquisition attempts.",
		},
		[]string{"user_type", "lock_type"},
	)
	SessionLockSuccessCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_session_lock_success_total",
			Help: "Total successful session lock acquisitions.",
		},
		[]string{"user_type", "lock_type"},
	)
	SessionLockFailureCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_session_lock_failure_total",
			Help: "Total failed session lock acquisitions.",
		},
		[]string{"user_type", "reason"},
	)
	GrpcPoolSizeGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "dws_grpc_pool_size",
			Help: "Total number of connections in the gRPC client pool.",
		},
	)
	GrpcPoolConnectionsCreatedTotalCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dws_grpc_pool_connections_created_total",
			Help: "Total new gRPC client connections established by the pool.",
		},
	)
	GrpcPoolConnectionsClosedTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_pool_connections_closed_total",
			Help: "Total gRPC client connections closed by the pool, partitioned by reason.",
		},
		[]string{"reason"},
	)
	GrpcPoolConnectionErrorsTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_pool_connection_errors_total",
			Help: "Total errors encountered with pooled gRPC client connections, partitioned by target pod.",
		},
		[]string{"target_pod_id"},
	)
	GrpcCircuitBreakerTrippedTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_circuitbreaker_tripped_total",
			Help: "Total times the circuit breaker has tripped for a target pod.",
		},
		[]string{"target_pod_id"},
	)
	WebsocketBufferUsedGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dws_websocket_buffer_used_count",
			Help: "Current number of messages in the WebSocket send buffer.",
		},
		[]string{"session_key"},
	)
	WebsocketBufferCapacityGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dws_websocket_buffer_capacity_count",
			Help: "Capacity of the WebSocket send buffer.",
		},
		[]string{"session_key"},
	)
	WebsocketMessagesDroppedTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_websocket_messages_dropped_total",
			Help: "Total messages dropped due to WebSocket backpressure.",
		},
		[]string{"session_key", "reason"},
	)
	WebsocketSlowClientsDisconnectedTotalCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dws_websocket_slow_clients_disconnected_total",
			Help: "Total slow WebSocket clients disconnected.",
		},
	)
)
func IncrementActiveConnections() {
	ActiveConnectionsGauge.Inc()
}
func DecrementActiveConnections() {
	ActiveConnectionsGauge.Dec()
}
func IncrementConnectionsTotal() {
	ConnectionsTotalCounter.Inc()
}
func ObserveConnectionDuration(durationSeconds float64) {
	ConnectionDurationHistogram.Observe(durationSeconds)
}
func IncrementMessagesReceived(messageType string) {
	MessagesReceivedCounter.WithLabelValues(messageType).Inc()
}
func IncrementMessagesSent(messageType string) {
	MessagesSentCounter.WithLabelValues(messageType).Inc()
}
func IncrementAuthSuccess(tokenType string) {
	AuthSuccessTotalCounter.WithLabelValues(tokenType).Inc()
}
func IncrementAuthFailure(tokenType string, reason string) {
	AuthFailureTotalCounter.WithLabelValues(tokenType, reason).Inc()
}
func IncrementSessionConflicts(userType string) {
	SessionConflictsTotalCounter.WithLabelValues(userType).Inc()
}
func IncrementNatsMessagesReceived(natsSubject string) {
	NatsMessagesReceivedCounter.WithLabelValues(natsSubject).Inc()
}
func IncrementGrpcMessagesSent(targetPodID string) {
	GrpcMessagesSentCounter.WithLabelValues(targetPodID).Inc()
}
func IncrementGrpcMessagesReceived(sourcePodID string) {
	GrpcMessagesReceivedCounter.WithLabelValues(sourcePodID).Inc()
}
func IncrementGrpcForwardRetryAttempts(targetPodID string) {
	GrpcForwardRetryAttemptsCounter.WithLabelValues(targetPodID).Inc()
}
func IncrementGrpcForwardRetrySuccess(targetPodID string) {
	GrpcForwardRetrySuccessCounter.WithLabelValues(targetPodID).Inc()
}
func IncrementGrpcForwardRetryFailure(targetPodID string) {
	GrpcForwardRetryFailureCounter.WithLabelValues(targetPodID).Inc()
}
func IncrementSessionLockAttempts(userType, lockType string) {
	SessionLockAttemptsCounter.WithLabelValues(userType, lockType).Inc()
}
func IncrementSessionLockSuccess(userType, lockType string) {
	SessionLockSuccessCounter.WithLabelValues(userType, lockType).Inc()
}
func IncrementSessionLockFailure(userType, reason string) {
	SessionLockFailureCounter.WithLabelValues(userType, reason).Inc()
}
func SetGrpcPoolSize(size float64) {
	GrpcPoolSizeGauge.Set(size)
}
func IncrementGrpcPoolConnectionsCreated() {
	GrpcPoolConnectionsCreatedTotalCounter.Inc()
}
func IncrementGrpcPoolConnectionsClosed(reason string) {
	GrpcPoolConnectionsClosedTotalCounter.WithLabelValues(reason).Inc()
}
func IncrementGrpcPoolConnectionErrors(targetPodID string) {
	GrpcPoolConnectionErrorsTotalCounter.WithLabelValues(targetPodID).Inc()
}
func IncrementGrpcCircuitBreakerTripped(targetPodID string) {
	GrpcCircuitBreakerTrippedTotalCounter.WithLabelValues(targetPodID).Inc()
}
func SetWebsocketBufferUsed(sessionKey string, count float64) {
	WebsocketBufferUsedGauge.WithLabelValues(sessionKey).Set(count)
}
func SetWebsocketBufferCapacity(sessionKey string, capacity float64) {
	WebsocketBufferCapacityGauge.WithLabelValues(sessionKey).Set(capacity)
}
func IncrementWebsocketMessagesDropped(sessionKey, reason string) {
	WebsocketMessagesDroppedTotalCounter.WithLabelValues(sessionKey, reason).Inc()
}
func IncrementWebsocketSlowClientsDisconnected() {
	WebsocketSlowClientsDisconnectedTotalCounter.Inc()
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
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
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
				var reasonForMetric string = "unknown_error"
				switch {
				case errors.Is(err, application.ErrTokenExpired):
					errCode = domain.ErrInvalidToken
					errMsg = "Admin token has expired."
					reasonForMetric = "expired"
				case errors.Is(err, crypto.ErrTokenDecryptionFailed),
					errors.Is(err, application.ErrTokenPayloadInvalid),
					errors.Is(err, crypto.ErrInvalidTokenFormat),
					errors.Is(err, crypto.ErrCiphertextTooShort):
					errCode = domain.ErrInvalidToken
					errMsg = "Admin token is invalid or malformed."
					errDetails = "Token format or content error."
					reasonForMetric = "invalid_format_or_content"
				case errors.Is(err, crypto.ErrInvalidAESKeySize),
					strings.Contains(err.Error(), "application not configured for admin token decryption"):
					errCode = domain.ErrInternal
					errMsg = "Server configuration error processing admin token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
					reasonForMetric = "config_error_aes_key"
				default:
					logger.Error(r.Context(), "Unexpected internal error during admin token processing", "path", r.URL.Path, "detailed_error", err.Error())
					errCode = domain.ErrInternal
					errMsg = "An unexpected error occurred while processing admin token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
					reasonForMetric = "internal_server_error"
				}
				metrics.IncrementAuthFailure("admin", reasonForMetric)
				domain.NewErrorResponse(errCode, errMsg, errDetails).WriteJSON(w, httpStatus)
				return
			}
			metrics.IncrementAuthSuccess("admin")
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
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
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
				var reasonForMetric string = "unknown_error"
				switch {
				case errors.Is(err, application.ErrTokenExpired):
					errCode = domain.ErrInvalidToken
					errMsg = "Company token has expired."
					reasonForMetric = "expired"
				case errors.Is(err, crypto.ErrTokenDecryptionFailed),
					errors.Is(err, application.ErrTokenPayloadInvalid),
					errors.Is(err, crypto.ErrInvalidTokenFormat),
					errors.Is(err, crypto.ErrCiphertextTooShort):
					errCode = domain.ErrInvalidToken
					errMsg = "Company token is invalid or malformed."
					errDetails = "Token format or content error."
					reasonForMetric = "invalid_format_or_content"
				case errors.Is(err, crypto.ErrInvalidAESKeySize),
					errors.New("application not configured for token decryption").Error() == err.Error():
					errCode = domain.ErrInternal
					errMsg = "Server configuration error processing token."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
					reasonForMetric = "config_error_aes_key"
				default:
					logger.Error(r.Context(), "Unexpected internal error during token processing", "path", r.URL.Path, "detailed_error", err.Error())
					errCode = domain.ErrInternal
					errMsg = "An unexpected error occurred."
					httpStatus = http.StatusInternalServerError
					errDetails = "Internal server error."
					reasonForMetric = "internal_server_error"
				}
				metrics.IncrementAuthFailure("company", reasonForMetric)
				errResp := domain.NewErrorResponse(errCode, errMsg, errDetails)
				errResp.WriteJSON(w, httpStatus)
				return
			}
			metrics.IncrementAuthSuccess("company")
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

## File: internal/adapters/websocket/conn.go
```go
package websocket
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)
const (
	backpressurePolicyDropOldest = "drop_oldest"
	backpressurePolicyBlock      = "block"
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
	currentChatID       string
	currentChatIDMu     sync.Mutex
	sessionKey      string
	messageBuffer   chan []byte
	bufferCapacity  int
	dropPolicy      string
	writerWg        sync.WaitGroup
	isWriterRunning bool
	writerMu        sync.Mutex
}
func NewConnection(
	connCtx context.Context,
	cancelFunc context.CancelFunc,
	wsConn *websocket.Conn,
	remoteAddr string,
	logger domain.Logger,
	cfgProvider config.Provider,
	sessionKey string,
) *Connection {
	appCfg := cfgProvider.Get().App
	bufferCap := appCfg.WebsocketMessageBufferSize
	if bufferCap <= 0 {
		bufferCap = 100
		logger.Warn(connCtx, "WebsocketMessageBufferSize not configured or invalid, using default", "default_size", bufferCap)
	}
	dropPol := strings.ToLower(appCfg.WebsocketBackpressureDropPolicy)
	if dropPol != backpressurePolicyDropOldest && dropPol != backpressurePolicyBlock {
		logger.Warn(connCtx, "Invalid WebsocketBackpressureDropPolicy, defaulting to drop_oldest", "configured_policy", appCfg.WebsocketBackpressureDropPolicy, "default_policy", backpressurePolicyDropOldest)
		dropPol = backpressurePolicyDropOldest
	}
	c := &Connection{
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
		currentChatID:       "",
		sessionKey:          sessionKey,
		messageBuffer:       make(chan []byte, bufferCap),
		bufferCapacity:      bufferCap,
		dropPolicy:          dropPol,
		isWriterRunning:     false,
	}
	metrics.SetWebsocketBufferCapacity(c.sessionKey, float64(c.bufferCapacity))
	c.startWriter()
	return c
}
func (c *Connection) startWriter() {
	c.writerMu.Lock()
	if c.isWriterRunning {
		c.writerMu.Unlock()
		return
	}
	c.isWriterRunning = true
	c.writerMu.Unlock()
	c.writerWg.Add(1)
	safego.Execute(c.connCtx, c.logger, fmt.Sprintf("WebSocketWriter-%s", c.sessionKey), func() {
		defer c.writerWg.Done()
		c.logger.Info(c.connCtx, "WebSocket writer goroutine started", "sessionKey", c.sessionKey)
		for {
			select {
			case <-c.connCtx.Done():
				c.logger.Info(c.connCtx, "Connection context done, stopping WebSocket writer.", "sessionKey", c.sessionKey)
				return
			case msgBytes, ok := <-c.messageBuffer:
				if !ok {
					c.logger.Info(c.connCtx, "Message buffer closed, stopping WebSocket writer.", "sessionKey", c.sessionKey)
					return
				}
				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
				ctxToWrite := c.connCtx
				var cancel context.CancelFunc
				writeTimeout := time.Duration(c.writeTimeoutSeconds) * time.Second
				if writeTimeout <= 0 {
					writeTimeout = 10 * time.Second
				}
				ctxToWrite, cancel = context.WithTimeout(c.connCtx, writeTimeout)
				c.mu.Lock()
				err := c.wsConn.Write(ctxToWrite, websocket.MessageText, msgBytes)
				c.mu.Unlock()
				cancel()
				if err != nil {
					c.logger.Error(c.connCtx, "Failed to write message from buffer to WebSocket", "error", err.Error(), "sessionKey", c.sessionKey)
					c.cancelConnCtxFunc()
					return
				}
			}
		}
	})
}
func (c *Connection) Context() context.Context {
	return c.connCtx
}
func (c *Connection) Close(statusCode websocket.StatusCode, reason string) error {
	c.logger.Info(c.connCtx, "Connection.Close called", "statusCode", statusCode, "reason", reason, "sessionKey", c.sessionKey)
	c.writerMu.Lock()
	if c.isWriterRunning {
		if c.messageBuffer != nil {
			close(c.messageBuffer)
		}
		c.isWriterRunning = false
	}
	c.writerMu.Unlock()
	c.writerWg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelConnCtxFunc != nil {
		currentCancelFunc := c.cancelConnCtxFunc
		c.cancelConnCtxFunc = nil
		currentCancelFunc()
	}
	if c.wsConn == nil {
		return errors.New("WebSocket connection is already nil")
	}
	err := c.wsConn.Close(statusCode, reason)
	c.wsConn = nil
	return err
}
func (c *Connection) CloseWithError(errResp domain.ErrorResponse, reason string) error {
	c.logger.Warn(c.connCtx, "Closing connection with error", "code", errResp.Code, "message", errResp.Message, "details", errResp.Details, "reason", reason, "sessionKey", c.sessionKey)
	errorMsgPayload := domain.NewErrorMessage(errResp)
	if err := c.WriteJSON(errorMsgPayload); err != nil {
		c.logger.Error(c.connCtx, "Failed to queue error message before closing connection",
			"error", err.Error(),
			"error_code", string(errResp.Code),
			"message", errResp.Message,
			"sessionKey", c.sessionKey)
	} else {
	}
	closeCode := errResp.ToWebSocketCloseCode()
	return c.Close(closeCode, reason)
}
func (c *Connection) WriteJSON(v interface{}) error {
	msgBytes, err := json.Marshal(v)
	if err != nil {
		c.logger.Error(c.connCtx, "Failed to marshal JSON for WriteJSON", "error", err.Error(), "sessionKey", c.sessionKey)
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	var messageTypeForMetric string = "unknown"
	if bm, ok := v.(domain.BaseMessage); ok {
		messageTypeForMetric = bm.Type
	}
	select {
	case <-c.connCtx.Done():
		c.logger.Warn(c.connCtx, "Connection context done, cannot write message to buffer", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
		return c.connCtx.Err()
	default:
	}
	c.writerMu.Lock()
	if !c.isWriterRunning {
		c.writerMu.Unlock()
		c.logger.Warn(c.connCtx, "Writer not running, cannot write message to buffer", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
		return fmt.Errorf("writer goroutine not running for session %s", c.sessionKey)
	}
	c.writerMu.Unlock()
	if len(c.messageBuffer) >= c.bufferCapacity {
		metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
		c.logger.Warn(c.connCtx, "WebSocket send buffer is full", "sessionKey", c.sessionKey, "capacity", c.bufferCapacity, "policy", c.dropPolicy, "messageType", messageTypeForMetric)
		if c.dropPolicy == backpressurePolicyDropOldest {
			select {
			case oldestMsg := <-c.messageBuffer:
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_dropped_oldest")
				c.logger.Info(c.connCtx, "Dropped oldest message from buffer due to backpressure", "sessionKey", c.sessionKey, "dropped_msg_len", len(oldestMsg), "messageType", messageTypeForMetric)
			default:
				c.logger.Error(c.connCtx, "Buffer full but could not dequeue oldest message (unexpected state)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
			}
			select {
			case c.messageBuffer <- msgBytes:
				metrics.IncrementMessagesSent(messageTypeForMetric)
				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
				return nil
			default:
				c.logger.Error(c.connCtx, "Failed to send message to buffer even after dropping oldest (buffer likely still full)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_post_drop_fail")
				return fmt.Errorf("failed to send to buffer for session %s after dropping oldest", c.sessionKey)
			}
		} else if c.dropPolicy == backpressurePolicyBlock {
			c.logger.Info(c.connCtx, "Blocking on WebSocket send buffer (policy: block)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
			select {
			case c.messageBuffer <- msgBytes:
				metrics.IncrementMessagesSent(messageTypeForMetric)
				metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
				return nil
			case <-c.connCtx.Done():
				c.logger.Warn(c.connCtx, "Connection context done while blocked on send buffer", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
				metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_block_ctx_done")
				return c.connCtx.Err()
			}
		} else {
			c.logger.Error(c.connCtx, "Unknown backpressure drop policy", "policy", c.dropPolicy, "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
			metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "unknown_policy")
			return fmt.Errorf("unknown backpressure policy: %s for session %s", c.dropPolicy, c.sessionKey)
		}
	}
	select {
	case c.messageBuffer <- msgBytes:
		metrics.IncrementMessagesSent(messageTypeForMetric)
		metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
		return nil
	default:
		c.logger.Warn(c.connCtx, "Buffer filled during non-blocking send attempt, retrying with policy", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
		if len(c.messageBuffer) >= c.bufferCapacity {
			if c.dropPolicy == backpressurePolicyDropOldest {
				select {
				case <-c.messageBuffer:
					metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_race_dropped_oldest")
				default:
				}
				select {
				case c.messageBuffer <- msgBytes:
					metrics.IncrementMessagesSent(messageTypeForMetric)
					metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
					return nil
				default:
					metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_race_drop_fail")
					return fmt.Errorf("failed to send to buffer (race) for session %s after dropping", c.sessionKey)
				}
			} else if c.dropPolicy == backpressurePolicyBlock {
				select {
				case c.messageBuffer <- msgBytes:
					metrics.IncrementMessagesSent(messageTypeForMetric)
					metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
					return nil
				case <-c.connCtx.Done():
					metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_full_race_block_ctx_done")
					return c.connCtx.Err()
				}
			}
		}
		select {
		case c.messageBuffer <- msgBytes:
			metrics.IncrementMessagesSent(messageTypeForMetric)
			metrics.SetWebsocketBufferUsed(c.sessionKey, float64(len(c.messageBuffer)))
			return nil
		case <-time.After(100 * time.Millisecond):
			c.logger.Error(c.connCtx, "Failed to send message to buffer after non-blocking attempt and re-check (unexpected)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
			metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_send_timeout_unexpected")
			return fmt.Errorf("timed out sending to buffer for session %s (unexpected state)", c.sessionKey)
		case <-c.connCtx.Done():
			c.logger.Warn(c.connCtx, "Connection context done while trying to send to buffer (unexpected state)", "sessionKey", c.sessionKey, "messageType", messageTypeForMetric)
			metrics.IncrementWebsocketMessagesDropped(c.sessionKey, "buffer_send_ctx_done_unexpected")
			return c.connCtx.Err()
		}
	}
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
	if c.wsConn == nil {
		return errors.New("cannot ping: WebSocket connection is nil (likely closed)")
	}
	ctxToWrite := c.connCtx
	var cancel context.CancelFunc
	writeTimeout := time.Duration(c.writeTimeoutSeconds) * time.Second
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}
	ctxToWrite, cancel = context.WithTimeout(ctxToWrite, writeTimeout)
	defer cancel()
	return c.wsConn.Ping(ctxToWrite)
}
func (c *Connection) GetCurrentChatID() string {
	c.currentChatIDMu.Lock()
	defer c.currentChatIDMu.Unlock()
	return c.currentChatID
}
func (c *Connection) SetCurrentChatID(chatID string) {
	c.currentChatIDMu.Lock()
	defer c.currentChatIDMu.Unlock()
	c.currentChatID = chatID
}
func (c *Connection) GetSessionKey() string {
	return c.sessionKey
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
	"strings"
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
	if err := ctx.Validate(); err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTokenPayloadInvalid, err)
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
	if err := adminCtx.Validate(); err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTokenPayloadInvalid, err)
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

## File: internal/domain/errors.go
```go
package domain
import (
	"encoding/json"
	"net/http"
	"github.com/coder/websocket"
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
	if httpStatusCode <= 0 {
		httpStatusCode = er.ToHTTPStatus()
	}
	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(er)
}
func (er ErrorResponse) ToWebSocketCloseCode() websocket.StatusCode {
	switch er.Code {
	case ErrInvalidAPIKey:
		return websocket.StatusCode(4401)
	case ErrInvalidToken, ErrUnauthorized, ErrForbidden:
		return websocket.StatusCode(4403)
	case ErrSessionConflict:
		return websocket.StatusCode(4402)
	case ErrRateLimitExceeded:
		return websocket.StatusCode(4429)
	case ErrBadRequest, ErrMethodNotAllowed:
		return websocket.StatusCode(4400)
	case ErrInternal, ErrSubscriptionFailure:
		return websocket.StatusCode(1011)
	default:
		return websocket.StatusCode(1011)
	}
}
func (er ErrorResponse) ToHTTPStatus() int {
	switch er.Code {
	case ErrInvalidAPIKey, ErrUnauthorized:
		return http.StatusUnauthorized
	case ErrInvalidToken, ErrForbidden:
		return http.StatusForbidden
	case ErrSessionConflict:
		return http.StatusConflict
	case ErrRateLimitExceeded:
		return http.StatusTooManyRequests
	case ErrBadRequest:
		return http.StatusBadRequest
	case ErrMethodNotAllowed:
		return http.StatusMethodNotAllowed
	case ErrInternal, ErrSubscriptionFailure:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
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
	CloseWithError(errResp ErrorResponse, reason string) error
	WriteJSON(v interface{}) error
	RemoteAddr() string
	Context() context.Context
	GetCurrentChatID() string
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
	google.golang.org/grpc v1.72.1
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
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
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250512202823-5a2f75b736a9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
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
	finalHandlerWithRequestID := middleware.RequestIDMiddleware(companyTokenAuthedHandler)
	mux.Handle("GET /ws/{company}/{agent}", finalHandlerWithRequestID)
	r.logger.Info(ctx, "WebSocket endpoint registered with RequestID, API Key and Company Token authentication", "pattern", "GET /ws/{company}/{agent}")
}
```

## File: internal/application/session_locking.go
```go
package application
import (
	"context"
	"fmt"
	"time"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)
const (
	maxSessionLockRetries   = 3
	initialLockRetryDelayMs = 50
	maxLockRetryDelayMs     = 500
	lockForceAcquireDelayMs = 100
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
	metrics.IncrementSessionLockAttempts("user", "initial_setnx")
	acquired, err := cm.sessionLocker.AcquireLock(ctx, sessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire session lock from store (initial attempt)",
			"error", err.Error(),
			"sessionKey", sessionKey,
		)
		metrics.IncrementSessionLockFailure("user", "redis_error_initial")
		return false, fmt.Errorf("failed to acquire session lock: %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Session lock acquired successfully (initial attempt)",
			"sessionKey", sessionKey,
			"podID", podID,
		)
		metrics.IncrementSessionLockSuccess("user", "initial_setnx")
		return true, nil
	}
	cm.logger.Warn(ctx, "Failed to acquire session lock (already held). Publishing kill message and starting retry logic.",
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
	currentDelayMs := initialLockRetryDelayMs
	for i := 0; i < maxSessionLockRetries; i++ {
		select {
		case <-time.After(time.Duration(currentDelayMs) * time.Millisecond):
			cm.logger.Info(ctx, "Retrying AcquireLock (SETNX) for session", "sessionKey", sessionKey, "podID", podID, "attempt", i+1, "delay_ms", currentDelayMs)
			metrics.IncrementSessionLockAttempts("user", "retry_setnx")
			acquired, err = cm.sessionLocker.AcquireLock(ctx, sessionKey, podID, sessionTTL)
			if err != nil {
				cm.logger.Error(ctx, fmt.Sprintf("Failed to retry AcquireLock (SETNX) on attempt %d", i+1), "sessionKey", sessionKey, "error", err.Error())
			} else if acquired {
				cm.logger.Info(ctx, fmt.Sprintf("Session lock acquired successfully on SETNX retry attempt %d", i+1), "sessionKey", sessionKey, "podID", podID)
				metrics.IncrementSessionLockSuccess("user", "retry_setnx")
				return true, nil
			}
			currentDelayMs *= 2
			if currentDelayMs > maxLockRetryDelayMs {
				currentDelayMs = maxLockRetryDelayMs
			}
		case <-ctx.Done():
			cm.logger.Warn(ctx, "Context cancelled during retry delay for session lock", "sessionKey", sessionKey, "error", ctx.Err())
			metrics.IncrementSessionLockFailure("user", "timeout_context_cancelled")
			return false, ctx.Err()
		}
	}
	cm.logger.Warn(ctx, "All SETNX retries failed. Attempting ForceAcquireLock (SET) for session after final delay.", "sessionKey", sessionKey, "podID", podID)
	select {
	case <-time.After(time.Duration(lockForceAcquireDelayMs) * time.Millisecond):
		metrics.IncrementSessionLockAttempts("user", "force_set")
		acquired, err = cm.sessionLocker.ForceAcquireLock(ctx, sessionKey, podID, sessionTTL)
		if err != nil {
			cm.logger.Error(ctx, "Failed to ForceAcquireLock (SET)", "sessionKey", sessionKey, "error", err.Error())
			metrics.IncrementSessionLockFailure("user", "redis_error_force_set")
			return false, fmt.Errorf("failed to ForceAcquireLock (SET): %w", err)
		}
		if acquired {
			cm.logger.Info(ctx, "Session lock acquired successfully using ForceAcquireLock (SET)", "sessionKey", sessionKey, "podID", podID)
			metrics.IncrementSessionLockSuccess("user", "force_set")
			return true, nil
		}
	case <-ctx.Done():
		cm.logger.Warn(ctx, "Context cancelled during final delay before ForceAcquireLock", "sessionKey", sessionKey, "error", ctx.Err())
		metrics.IncrementSessionLockFailure("user", "timeout_context_cancelled")
		return false, ctx.Err()
	}
	cm.logger.Error(ctx, "All attempts to acquire session lock failed, including ForceAcquireLock.", "sessionKey", sessionKey)
	metrics.IncrementSessionLockFailure("user", "all_attempts_failed")
	return false, fmt.Errorf("all attempts to acquire session lock failed for key %s", sessionKey)
}
func (cm *ConnectionManager) AcquireAdminSessionLockOrNotify(ctx context.Context, adminID string) (bool, error) {
	cfg := cm.configProvider.Get()
	podID := cfg.Server.PodID
	if podID == "" {
		cm.logger.Error(ctx, "PodID is not configured. Admin session locking will not work correctly.", "operation", "AcquireAdminSessionLockOrNotify")
		metrics.IncrementSessionLockFailure("admin", "config_error_podid")
		return false, fmt.Errorf("podID is not configured")
	}
	adminSessionKey := rediskeys.AdminSessionKey(adminID)
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	cm.logger.Info(ctx, "Attempting to acquire admin session lock",
		"adminSessionKey", adminSessionKey,
		"podID", podID,
		"ttlSeconds", sessionTTL.Seconds(),
	)
	metrics.IncrementSessionLockAttempts("admin", "initial_setnx")
	acquired, err := cm.sessionLocker.AcquireLock(ctx, adminSessionKey, podID, sessionTTL)
	if err != nil {
		cm.logger.Error(ctx, "Failed to acquire admin session lock from store (initial attempt)", "error", err.Error(), "adminSessionKey", adminSessionKey)
		metrics.IncrementSessionLockFailure("admin", "redis_error_initial")
		return false, fmt.Errorf("failed to acquire admin session lock: %w", err)
	}
	if acquired {
		cm.logger.Info(ctx, "Admin session lock acquired successfully (initial attempt)", "adminSessionKey", adminSessionKey, "podID", podID)
		metrics.IncrementSessionLockSuccess("admin", "initial_setnx")
		return true, nil
	}
	cm.logger.Warn(ctx, "Failed to acquire admin session lock (already held). Publishing admin kill message and starting retry logic.",
		"adminSessionKey", adminSessionKey,
		"newPodIDAttempting", podID,
	)
	killChannel := rediskeys.AdminSessionKillChannelKey(adminID)
	killMsg := domain.KillSwitchMessage{NewPodID: podID}
	if pubErr := cm.killSwitchPublisher.PublishSessionKill(ctx, killChannel, killMsg); pubErr != nil {
		cm.logger.Error(ctx, "Failed to publish admin session kill message", "channel", killChannel, "error", pubErr.Error())
	}
	currentDelayMs := initialLockRetryDelayMs
	for i := 0; i < maxSessionLockRetries; i++ {
		select {
		case <-time.After(time.Duration(currentDelayMs) * time.Millisecond):
			cm.logger.Info(ctx, "Retrying AcquireLock (SETNX) for admin session", "adminSessionKey", adminSessionKey, "podID", podID, "attempt", i+1, "delay_ms", currentDelayMs)
			metrics.IncrementSessionLockAttempts("admin", "retry_setnx")
			acquired, err = cm.sessionLocker.AcquireLock(ctx, adminSessionKey, podID, sessionTTL)
			if err != nil {
				cm.logger.Error(ctx, fmt.Sprintf("Failed to retry AcquireLock (SETNX) for admin on attempt %d", i+1), "adminSessionKey", adminSessionKey, "error", err.Error())
			} else if acquired {
				cm.logger.Info(ctx, fmt.Sprintf("Admin session lock acquired successfully on SETNX retry attempt %d", i+1), "adminSessionKey", adminSessionKey, "podID", podID)
				metrics.IncrementSessionLockSuccess("admin", "retry_setnx")
				return true, nil
			}
			currentDelayMs *= 2
			if currentDelayMs > maxLockRetryDelayMs {
				currentDelayMs = maxLockRetryDelayMs
			}
		case <-ctx.Done():
			cm.logger.Warn(ctx, "Context cancelled during retry delay for admin session lock", "adminSessionKey", adminSessionKey, "error", ctx.Err())
			metrics.IncrementSessionLockFailure("admin", "timeout_context_cancelled")
			return false, ctx.Err()
		}
	}
	cm.logger.Warn(ctx, "All SETNX retries failed for admin. Attempting ForceAcquireLock (SET) after final delay.", "adminSessionKey", adminSessionKey, "podID", podID)
	select {
	case <-time.After(time.Duration(lockForceAcquireDelayMs) * time.Millisecond):
		metrics.IncrementSessionLockAttempts("admin", "force_set")
		acquired, err = cm.sessionLocker.ForceAcquireLock(ctx, adminSessionKey, podID, sessionTTL)
		if err != nil {
			cm.logger.Error(ctx, "Failed to ForceAcquireLock (SET) for admin session", "adminSessionKey", adminSessionKey, "error", err.Error())
			metrics.IncrementSessionLockFailure("admin", "redis_error_force_set")
			return false, fmt.Errorf("failed to ForceAcquireLock (SET) for admin: %w", err)
		}
		if acquired {
			cm.logger.Info(ctx, "Admin session lock acquired successfully using ForceAcquireLock (SET)", "adminSessionKey", adminSessionKey, "podID", podID)
			metrics.IncrementSessionLockSuccess("admin", "force_set")
			return true, nil
		}
	case <-ctx.Done():
		cm.logger.Warn(ctx, "Context cancelled during final delay before ForceAcquireLock for admin", "adminSessionKey", adminSessionKey, "error", ctx.Err())
		metrics.IncrementSessionLockFailure("admin", "timeout_context_cancelled")
		return false, ctx.Err()
	}
	cm.logger.Error(ctx, "All attempts to acquire admin session lock failed, including ForceAcquireLock.", "adminSessionKey", adminSessionKey)
	metrics.IncrementSessionLockFailure("admin", "all_attempts_failed")
	return false, fmt.Errorf("all attempts to acquire admin session lock failed for key %s", adminSessionKey)
}
```

## File: internal/application/session_renewal.go
```go
package application
import (
	"context"
	"fmt"
	"time"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)
func (cm *ConnectionManager) StartResourceRenewalLoop(appCtx context.Context) {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	routeTTL := time.Duration(cfg.App.RouteTTLSeconds) * time.Second
	podID := cfg.Server.PodID
	if renewalInterval <= 0 {
		cm.logger.Warn(appCtx, "Resource renewal interval is not configured or invalid; renewal loop will not start.", "intervalSeconds", cfg.App.TTLRefreshIntervalSeconds)
		return
	}
	if podID == "" {
		cm.logger.Error(appCtx, "PodID is not configured. Resource renewal will not work correctly.")
		return
	}
	cm.logger.Info(appCtx, "Starting resource renewal loop",
		"renewalInterval", renewalInterval.String(),
		"sessionTTL", sessionTTL.String(),
		"routeTTL", routeTTL.String(),
		"podID", podID,
	)
	cm.renewalWg.Add(1)
	safego.Execute(appCtx, cm.logger, "ResourceRenewalLoop", func() {
		defer cm.renewalWg.Done()
		ticker := time.NewTicker(renewalInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cm.logger.Debug(appCtx, "Resource renewal tick: attempting to renew active session locks and routes")
				cm.activeConnections.Range(func(key, value interface{}) bool {
					sessionKey, okSessionKey := key.(string)
					conn, okConn := value.(domain.ManagedConnection)
					if !okSessionKey || !okConn {
						cm.logger.Error(appCtx, "Invalid type in activeConnections map during renewal", "key_type", fmt.Sprintf("%T", key), "value_type", fmt.Sprintf("%T", value))
						return true
					}
					connCtx := conn.Context()
					renewalOpCtx, cancelOp := context.WithTimeout(appCtx, 5*time.Second)
					defer cancelOp()
					if cm.sessionLocker != nil && sessionTTL > 0 {
						refreshed, err := cm.sessionLocker.RefreshLock(renewalOpCtx, sessionKey, podID, sessionTTL)
						if err != nil {
							cm.logger.Error(connCtx, "Error refreshing session lock", "sessionKey", sessionKey, "podID", podID, "error", err.Error())
						} else if refreshed {
							cm.logger.Debug(connCtx, "Successfully refreshed session lock", "sessionKey", sessionKey, "podID", podID, "newTTL", sessionTTL.String())
						} else {
							cm.logger.Warn(connCtx, "Failed to refresh session lock (not owned or expired)", "sessionKey", sessionKey, "podID", podID)
						}
					} else {
						cm.logger.Debug(connCtx, "Skipping session lock renewal (not configured or TTL is zero)", "sessionKey", sessionKey)
					}
					if cm.routeRegistry != nil && routeTTL > 0 {
						companyID, _ := connCtx.Value(contextkeys.CompanyIDKey).(string)
						agentID, _ := connCtx.Value(contextkeys.AgentIDKey).(string)
						if companyID == "" || agentID == "" {
							cm.logger.Error(connCtx, "Missing companyID or agentID in connection context, cannot renew routes", "sessionKey", sessionKey)
							return true
						}
						chatRouteKey := rediskeys.RouteKeyChats(companyID, agentID)
						refreshedChat, errChat := cm.routeRegistry.RefreshRouteTTL(renewalOpCtx, chatRouteKey, podID, routeTTL)
						if errChat != nil {
							cm.logger.Error(connCtx, "Error refreshing chat route TTL", "routeKey", chatRouteKey, "podID", podID, "error", errChat.Error())
						} else if refreshedChat {
							cm.logger.Debug(connCtx, "Successfully refreshed chat route TTL", "routeKey", chatRouteKey, "podID", podID, "newTTL", routeTTL.String())
						} else {
							cm.logger.Warn(connCtx, "Failed to refresh chat route TTL (pod not member or key expired)", "routeKey", chatRouteKey, "podID", podID)
						}
						currentChatID := conn.GetCurrentChatID()
						if currentChatID != "" {
							messageRouteKey := rediskeys.RouteKeyMessages(companyID, agentID, currentChatID)
							refreshedMsg, errMsg := cm.routeRegistry.RefreshRouteTTL(renewalOpCtx, messageRouteKey, podID, routeTTL)
							if errMsg != nil {
								cm.logger.Error(connCtx, "Error refreshing message route TTL", "routeKey", messageRouteKey, "podID", podID, "error", errMsg.Error())
							} else if refreshedMsg {
								cm.logger.Debug(connCtx, "Successfully refreshed message route TTL", "routeKey", messageRouteKey, "podID", podID, "newTTL", routeTTL.String())
							} else {
								cm.logger.Warn(connCtx, "Failed to refresh message route TTL (pod not member or key expired)", "routeKey", messageRouteKey, "podID", podID)
							}
						}
					} else {
						cm.logger.Debug(connCtx, "Skipping route renewal (not configured or TTL is zero)", "sessionKey", sessionKey)
					}
					return true
				})
			case <-cm.renewalStopChan:
				cm.logger.Info(appCtx, "Resource renewal loop stopping as requested.")
				return
			case <-appCtx.Done():
				cm.logger.Info(appCtx, "Resource renewal loop stopping due to application context cancellation.")
				return
			}
		}
	})
}
func (cm *ConnectionManager) StopResourceRenewalLoop() {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	if renewalInterval <= 0 || cfg.Server.PodID == "" { // Check if loop was likely started
		cm.logger.Info(context.Background(), "Resource renewal loop was not started or podID not set, nothing to stop.")
		return
	}
	cm.logger.Info(context.Background(), "Attempting to stop resource renewal loop...")
	close(cm.renewalStopChan) // Signal the loop to stop
	cm.renewalWg.Wait()       // Wait for the goroutine to finish
	cm.logger.Info(context.Background(), "Resource renewal loop stopped.")
}
```

## File: internal/domain/auth.go
```go
package domain
import (
	"fmt"
	"time"
)
type AuthenticatedUserContext struct {
	CompanyID string    `json:"company_id"`
	AgentID   string    `json:"agent_id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"-"`
}
func (auc *AuthenticatedUserContext) Validate() error {
	if auc.CompanyID == "" || auc.AgentID == "" || auc.UserID == "" || auc.ExpiresAt.IsZero() {
		return fmt.Errorf("missing essential fields (company_id, agent_id, user_id, expires_at)")
	}
	if time.Now().After(auc.ExpiresAt) {
		return fmt.Errorf("token expired at %v", auc.ExpiresAt)
	}
	return nil
}
type AdminUserContext struct {
	AdminID              string `json:"admin_id"`
	CompanyIDRestriction string `json:"company_id_restriction,omitempty"`
	SubscribedCompanyID string    `json:"subscribed_company_id,omitempty"`
	SubscribedAgentID   string    `json:"subscribed_agent_id,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	Token               string    `json:"-"`
}
func (auc *AdminUserContext) Validate() error {
	if auc.AdminID == "" || auc.ExpiresAt.IsZero() {
		return fmt.Errorf("missing essential fields (admin_id, expires_at) in admin token")
	}
	if time.Now().After(auc.ExpiresAt) {
		return fmt.Errorf("admin token expired at %v", auc.ExpiresAt)
	}
	return nil
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
	logger                 domain.Logger
	configProvider         config.Provider
	sessionLocker          domain.SessionLockManager
	killSwitchPublisher    domain.KillSwitchPublisher
	killSwitchSubscriber   domain.KillSwitchSubscriber
	routeRegistry          domain.RouteRegistry
	activeConnections      sync.Map
	activeAdminConnections sync.Map
	renewalStopChan chan struct{}
	renewalWg       sync.WaitGroup
}
func NewConnectionManager(
	logger domain.Logger,
	configProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPublisher domain.KillSwitchPublisher,
	killSwitchSubscriber domain.KillSwitchSubscriber,
	routeRegistry domain.RouteRegistry,
) *ConnectionManager {
	return &ConnectionManager{
		logger:                 logger,
		configProvider:         configProvider,
		sessionLocker:          sessionLocker,
		killSwitchPublisher:    killSwitchPublisher,
		killSwitchSubscriber:   killSwitchSubscriber,
		routeRegistry:          routeRegistry,
		activeConnections:      sync.Map{},
		activeAdminConnections: sync.Map{},
		renewalStopChan:        make(chan struct{}),
	}
}
func (cm *ConnectionManager) RouteRegistrar() domain.RouteRegistry {
	return cm.routeRegistry
}
```

## File: internal/application/kill_switch.go
```go
package application
import (
	"context"
	"fmt"
	"strings"
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
	errResp := domain.NewErrorResponse(domain.ErrSessionConflict, "Session conflict", "Session taken over by another connection")
	if err := managedConn.CloseWithError(errResp, "SessionConflict: Session taken over by another connection"); err != nil {
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
	errResp := domain.NewErrorResponse(domain.ErrSessionConflict, "Session conflict", "Admin session taken over by another connection")
	if err := managedConn.CloseWithError(errResp, "AdminSessionConflict: Session taken over by another connection"); err != nil {
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

## File: internal/adapters/nats/consumer.go
```go
package nats
import (
	"context"
	"fmt"
	"strings"
	"time"
	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)
type natsSubscriptionWrapper struct {
	*nats.Subscription
}
func (nsw *natsSubscriptionWrapper) Drain() error {
	return nsw.Subscription.Drain()
}
func (nsw *natsSubscriptionWrapper) IsValid() bool {
	return nsw.Subscription.IsValid()
}
func (nsw *natsSubscriptionWrapper) Subject() string {
	return nsw.Subscription.Subject
}
type ConsumerAdapter struct {
	nc                *nats.Conn
	js                nats.JetStreamContext
	logger            domain.Logger
	cfgProvider       config.Provider
	appName           string
	natsMaxAckPending int
}
func NewConsumerAdapter(ctx context.Context, cfgProvider config.Provider, appLogger domain.Logger) (*ConsumerAdapter, func(), error) {
	appFullCfg := cfgProvider.Get()
	natsCfg := appFullCfg.NATS
	appName := appFullCfg.App.ServiceName
	natsMaxAckPending := appFullCfg.App.NATSMaxAckPending
	natsAckWaitSeconds := appFullCfg.App.NatsAckWaitSeconds
	if natsAckWaitSeconds <= 0 {
		natsAckWaitSeconds = 30
		appLogger.Warn(ctx, "NatsAckWaitSeconds not configured or invalid, defaulting to 30s")
	}
	appLogger.Info(ctx, "Attempting to connect to NATS server", "url", natsCfg.URL)
	natsOptions := []nats.Option{
		nats.Name(fmt.Sprintf("%s-consumer-%s", appName, appFullCfg.Server.PodID)),
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
	}
	if natsCfg.RetryOnFailedConnect {
		natsOptions = append(natsOptions, nats.RetryOnFailedConnect(true))
	} else {
	}
	if natsCfg.MaxReconnects != 0 {
		natsOptions = append(natsOptions, nats.MaxReconnects(natsCfg.MaxReconnects))
	}
	if natsCfg.ReconnectWaitSeconds > 0 {
		natsOptions = append(natsOptions, nats.ReconnectWait(time.Duration(natsCfg.ReconnectWaitSeconds)*time.Second))
	}
	if natsCfg.ConnectTimeoutSeconds > 0 {
		natsOptions = append(natsOptions, nats.Timeout(time.Duration(natsCfg.ConnectTimeoutSeconds)*time.Second))
	}
	if natsCfg.PingIntervalSeconds > 0 {
		natsOptions = append(natsOptions, nats.PingInterval(time.Duration(natsCfg.PingIntervalSeconds)*time.Second))
	}
	if natsCfg.MaxPingsOut > 0 {
		natsOptions = append(natsOptions, nats.MaxPingsOutstanding(natsCfg.MaxPingsOut))
	}
	nc, err := nats.Connect(natsCfg.URL, natsOptions...)
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
		cfgProvider:       cfgProvider,
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
func (a *ConsumerAdapter) SubscribeToChats(ctx context.Context, companyID, agentID string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}
	subject := fmt.Sprintf("wa.%s.%s.chats", companyID, agentID)
	queueGroup := "ws_fanout"
	a.logger.Info(ctx, "Attempting to subscribe to NATS subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"stream_name", a.cfgProvider.Get().NATS.StreamName,
		"consumer_name", a.cfgProvider.Get().NATS.ConsumerName,
	)
	durableName := a.cfgProvider.Get().NATS.ConsumerName
	ackWait := time.Duration(a.cfgProvider.Get().App.NatsAckWaitSeconds) * time.Second
	if ackWait <= 0 {
		ackWait = 30 * time.Second
	}
	natsHandler := nats.MsgHandler(handler)
	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		natsHandler,
		nats.Durable(durableName),
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckWait(ackWait),
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
	return &natsSubscriptionWrapper{Subscription: sub}, nil
}
func (a *ConsumerAdapter) SubscribeToChatMessages(ctx context.Context, companyID, agentID, chatID string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}
	subject := rediskeys.RouteKeyMessages(companyID, agentID, chatID)
	subject = fmt.Sprintf("wa.%s.%s.messages.%s", companyID, agentID, chatID)
	queueGroup := "ws_fanout"
	durableName := a.cfgProvider.Get().NATS.ConsumerName
	ackWaitMessages := time.Duration(a.cfgProvider.Get().App.NatsAckWaitSeconds) * time.Second
	if ackWaitMessages <= 0 {
		ackWaitMessages = 30 * time.Second
	}
	a.logger.Info(ctx, "Attempting to subscribe to NATS chat messages subject",
		"subject", subject,
		"queue_group", queueGroup,
		"durable_name", durableName,
	)
	natsHandler := nats.MsgHandler(handler)
	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		natsHandler,
		nats.Durable(durableName+"_messages"),
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckWait(ackWaitMessages),
		nats.MaxAckPending(a.natsMaxAckPending),
	)
	if err != nil {
		a.logger.Error(ctx, "Failed to subscribe to NATS chat messages subject",
			"subject", subject,
			"queue_group", queueGroup,
			"durable_name", durableName+"_messages",
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to subscribe to NATS chat messages subject %s: %w", subject, err)
	}
	a.logger.Info(ctx, "Successfully subscribed to NATS chat messages subject",
		"subject", subject,
		"queue_group", queueGroup,
		"durable_name", durableName+"_messages",
	)
	return &natsSubscriptionWrapper{Subscription: sub}, nil
}
func ParseNATSMessageSubject(subject string) (companyID, agentID, chatID string, err error) {
	parts := strings.Split(subject, ".")
	if len(parts) != 5 || parts[0] != "wa" || parts[3] != "messages" {
		err = fmt.Errorf("invalid NATS message subject format: %s", subject)
		return
	}
	companyID = parts[1]
	agentID = parts[2]
	chatID = parts[4]
	if companyID == "" || agentID == "" || chatID == "" {
		err = fmt.Errorf("empty companyID, agentID, or chatID in NATS subject: %s", subject)
		return
	}
	return
}
func (a *ConsumerAdapter) SubscribeToAgentEvents(ctx context.Context, companyIDPattern, agentIDPattern string, handler domain.NatsMessageHandler) (domain.NatsMessageSubscription, error) {
	if a.js == nil {
		return nil, fmt.Errorf("JetStream context is not initialized")
	}
	subject := fmt.Sprintf("wa.%s.%s.agents", companyIDPattern, agentIDPattern)
	queueGroup := "ws_fanout"
	a.logger.Info(ctx, "Attempting to subscribe to NATS agent events subject with queue group",
		"subject", subject,
		"queue_group", queueGroup,
		"stream_name", a.cfgProvider.Get().NATS.StreamName,
		"consumer_name", a.cfgProvider.Get().NATS.ConsumerName,
	)
	durableName := a.cfgProvider.Get().NATS.ConsumerName
	ackWaitAdmin := time.Duration(a.cfgProvider.Get().App.NatsAckWaitSeconds) * time.Second
	if ackWaitAdmin <= 0 {
		ackWaitAdmin = 30 * time.Second
	}
	natsHandler := nats.MsgHandler(handler)
	sub, err := a.js.QueueSubscribe(
		subject,
		queueGroup,
		natsHandler,
		nats.Durable(durableName+"_admin_agents"),
		nats.DeliverAll(),
		nats.ManualAck(),
		nats.AckWait(ackWaitAdmin),
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
	return &natsSubscriptionWrapper{Subscription: sub}, nil
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
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
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
	natsAdapter    domain.NatsConsumer
}
func NewAdminHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter domain.NatsConsumer) *AdminHandler {
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
		metrics.IncrementSessionConflicts("admin")
		domain.NewErrorResponse(domain.ErrSessionConflict, "Admin session already active elsewhere.", "").WriteJSON(w, http.StatusConflict)
		return
	}
	h.logger.Info(r.Context(), "Admin session lock successfully acquired", "admin_session_key", adminSessionKey)
	wsConnLifetimeCtx, cancelWsConnLifetimeCtx := context.WithCancel(r.Context())
	var wrappedConn *Connection
	startTime := time.Now()
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
	metrics.IncrementConnectionsTotal()
	wrappedConn = NewConnection(wsConnLifetimeCtx, cancelWsConnLifetimeCtx, c, r.RemoteAddr, h.logger, h.configProvider, adminSessionKey)
	h.logger.Info(wrappedConn.Context(), "Admin WebSocket connection established",
		"remoteAddr", wrappedConn.RemoteAddr(),
		"subprotocol", c.Subprotocol(),
		"admin_id", adminCtx.AdminID,
		"admin_session_key", adminSessionKey,
	)
	h.connManager.RegisterConnection(adminSessionKey, wrappedConn, "", "") // Pass empty strings for company/agent for admin conns
	defer func() {
		h.logger.Info(wrappedConn.Context(), "Admin connection management goroutine finished. Deregistering admin connection.", "admin_session_key", adminSessionKey)
		duration := time.Since(startTime).Seconds()
		metrics.ObserveConnectionDuration(duration)
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
	readyMessage := domain.NewReadyMessage()
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to admin client", "error", err.Error(), "admin_id", adminInfo.AdminID)
		return
	}
	metrics.IncrementMessagesSent(domain.MessageTypeReady)
	h.logger.Info(connCtx, "Sent 'ready' message to admin client", "admin_id", adminInfo.AdminID)
	var natsSubscription domain.NatsMessageSubscription
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
			metrics.IncrementNatsMessagesReceived(msg.Subject) // Increment NATS received metric for admin
			// Start: request_id handling for NATS message
			natsRequestID := msg.Header.Get(middleware.XRequestIDHeader)
			if natsRequestID == "" {
				natsRequestID = uuid.NewString()
				h.logger.Debug(connCtx, "Generated new request_id for Admin NATS message", "subject", msg.Subject, "new_request_id", natsRequestID, "admin_id", adminInfo.AdminID)
			} else {
				h.logger.Debug(connCtx, "Using existing request_id from Admin NATS message header", "subject", msg.Subject, "request_id", natsRequestID, "admin_id", adminInfo.AdminID)
			}
			msgCtx := context.WithValue(connCtx, contextkeys.RequestIDKey, natsRequestID)
			h.logger.Info(msgCtx, "Admin NATS: Received message on agent events subject",
				"subject", msg.Subject, "data_len", len(msg.Data), "admin_id", adminInfo.AdminID,
			)
			var eventPayload domain.EnrichedEventPayload
			if err := json.Unmarshal(msg.Data, &eventPayload); err != nil {
				h.logger.Error(msgCtx, "Admin NATS: Failed to unmarshal agent event payload", "subject", msg.Subject, "error", err.Error(), "admin_id", adminInfo.AdminID)
				_ = msg.Ack()
				return
			}
			wsMessage := domain.NewEventMessage(eventPayload)
			if err := conn.WriteJSON(wsMessage); err != nil {
				h.logger.Error(msgCtx, "Admin NATS: Failed to forward agent event to WebSocket", "subject", msg.Subject, "error", err.Error(), "admin_id", adminInfo.AdminID)
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeEvent)
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
			if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorMsg)); sendErr != nil {
				h.logger.Error(connCtx, "Failed to send NATS subscription error to admin client", "error", sendErr.Error())
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeError)
			}
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
						h.logger.Error(connCtx, "Failed to send admin ping", "error", err.Error(), "admin_id", adminInfo.AdminID)
						pingCancel()
						errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to send ping", err.Error())
						conn.CloseWithError(errResp, "Admin Ping failure")
						return
					}
					pingCancel()
					h.logger.Debug(connCtx, "Sent ping to admin client", "admin_id", adminInfo.AdminID)
					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Admin Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr(), "admin_id", adminInfo.AdminID)
						errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No pong responses received within the configured duration.")
						conn.CloseWithError(errResp, "Admin Pong timeout")
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
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No message received within configured timeout period.")
				conn.CloseWithError(errResp, "Admin Pong timeout")
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
		if msgType == websocket.MessageText {
			metrics.IncrementMessagesReceived("admin_text_message")
			h.logger.Info(connCtx, "Admin client sent a text message.", "payload", string(p))
		} else if msgType == websocket.MessageBinary {
			metrics.IncrementMessagesReceived("admin_binary_message")
		}
	}
}
```

## File: internal/application/connection_registry.go
```go
package application
import (
	"context"
	"fmt"
	"time"
	"github.com/coder/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)
func (cm *ConnectionManager) RegisterConnection(sessionKey string, conn domain.ManagedConnection, companyID, agentID string) {
	cm.activeConnections.Store(sessionKey, conn)
	metrics.IncrementActiveConnections()
	cm.logger.Info(conn.Context(), "WebSocket connection registered with ConnectionManager", "sessionKey", sessionKey, "remoteAddr", conn.RemoteAddr())
	cfg := cm.configProvider.Get()
	podID := cfg.Server.PodID
	routeTTL := time.Duration(cfg.App.RouteTTLSeconds) * time.Second
	if routeTTL <= 0 {
		routeTTL = 30 * time.Second
		cm.logger.Warn(conn.Context(), "RouteTTLSeconds not configured or zero, using default 30s for chat route registration", "sessionKey", sessionKey)
	}
	if podID == "" {
		cm.logger.Error(conn.Context(), "PodID is not configured. Cannot register chat route.", "sessionKey", sessionKey)
		return
	}
	if cm.routeRegistry != nil {
		err := cm.routeRegistry.RegisterChatRoute(conn.Context(), companyID, agentID, podID, routeTTL)
		if err != nil {
			cm.logger.Error(conn.Context(), "Failed to register chat route on connection registration",
				"sessionKey", sessionKey, "companyID", companyID, "agentID", agentID, "podID", podID, "error", err.Error(),
			)
		} else {
			cm.logger.Info(conn.Context(), "Successfully registered chat route on connection registration",
				"sessionKey", sessionKey, "companyID", companyID, "agentID", agentID, "podID", podID, "ttl", routeTTL.String(),
			)
		}
	} else {
		cm.logger.Error(conn.Context(), "RouteRegistry is nil in ConnectionManager. Cannot register chat route.", "sessionKey", sessionKey)
	}
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
func (cm *ConnectionManager) GracefullyCloseAllConnections(closeCode websocket.StatusCode, reason string) {
	cm.logger.Info(context.Background(), "Initiating graceful closure of all active WebSocket connections...", "code", closeCode, "reason", reason)
	closedCount := 0
	errResp := domain.NewErrorResponse(domain.ErrInternal, "Service shutting down", "The WebSocket service is being gracefully terminated.")
	cm.activeConnections.Range(func(key, value interface{}) bool {
		sessionKey, okSessionKey := key.(string)
		conn, okConn := value.(domain.ManagedConnection)
		if !okSessionKey || !okConn {
			cm.logger.Error(context.Background(), "Invalid type in activeConnections map during graceful shutdown", "key_type", fmt.Sprintf("%T", key), "value_type", fmt.Sprintf("%T", value))
			return true
		}
		cm.logger.Info(conn.Context(), "Sending close frame to WebSocket connection", "sessionKey", sessionKey, "remoteAddr", conn.RemoteAddr(), "code", closeCode)
		if err := conn.CloseWithError(errResp, reason); err != nil {
			cm.logger.Warn(conn.Context(), "Error sending close frame during graceful shutdown (will be forcibly closed)", "sessionKey", sessionKey, "error", err.Error())
		}
		closedCount++
		return true
	})
	cm.activeAdminConnections.Range(func(key, value interface{}) bool {
		adminSessionKey, okSessionKey := key.(string)
		conn, okConn := value.(domain.ManagedConnection)
		if !okSessionKey || !okConn {
			cm.logger.Error(context.Background(), "Invalid type in activeAdminConnections map during graceful shutdown", "key_type", fmt.Sprintf("%T", key), "value_type", fmt.Sprintf("%T", value))
			return true
		}
		cm.logger.Info(conn.Context(), "Sending close frame to admin WebSocket connection", "adminSessionKey", adminSessionKey, "remoteAddr", conn.RemoteAddr(), "code", closeCode)
		if err := conn.CloseWithError(errResp, reason); err != nil {
			cm.logger.Warn(conn.Context(), "Error sending close frame to admin connection during graceful shutdown (will be forcibly closed)", "adminSessionKey", adminSessionKey, "error", err.Error())
		}
		closedCount++
		return true
	})
	cm.logger.Info(context.Background(), "Graceful close frames sent to active connections", "count", closedCount)
}
```

## File: config/config.yaml
```yaml
server:
  http_port: 8080
  grpc_port: 50051
  pod_id: "" # This should be set via ENV (e.g., POD_IP via Downward API)
  enable_reflection: false # Default to false for production
# NATS Configuration
nats:
  url: "nats://nats:4222"
  stream_name: "wa_stream"
  consumer_name: "ws_fanout"
  connect_timeout_seconds: 5
  reconnect_wait_seconds: 2
  max_reconnects: 5
  ping_interval_seconds: 120
  max_pings_out: 2
  retry_on_failed_connect: true
redis:
  address: "redis:6379"
  session_lock_retry_delay_ms: 250
  nats_ack_wait_seconds: 30
  grpc_client_forward_timeout_seconds: 5
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
  pong_wait_seconds: 60
  write_timeout_seconds: 10
  max_missed_pongs: 2
  session_ttl_seconds: 30
  route_ttl_seconds: 30
  ttl_refresh_interval_seconds: 10
  nats_max_ack_pending: 5000
  session_lock_retry_delay_ms: 250
  nats_ack_wait_seconds: 30
  grpc_client_forward_timeout_seconds: 5
  read_timeout_seconds: 10
  idle_timeout_seconds: 60
  websocket_compression_mode: "disabled"
  websocket_compression_threshold: 1024
  websocket_development_insecure_skip_verify: false
  grpc_pool_idle_timeout_seconds: 300
  grpc_pool_health_check_interval_seconds: 60
  grpc_circuitbreaker_fail_threshold: 5
  grpc_circuitbreaker_open_duration_seconds: 30
  websocket_message_buffer_size: 100
  websocket_backpressure_drop_policy: "drop_oldest"
  websocket_slow_client_latency_ms: 5000
  websocket_slow_client_disconnect_threshold_ms: 30000
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
	HTTPPort         int    `mapstructure:"http_port"`
	GRPCPort         int    `mapstructure:"grpc_port"`
	PodID            string `mapstructure:"pod_id"`
	EnableReflection bool   `mapstructure:"enable_reflection"`
}
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
type RedisConfig struct {
	Address                                string `mapstructure:"address"`
	Password                               string `mapstructure:"password"`
	DB                                     int    `mapstructure:"db"`
	WebsocketCompressionMode               string `mapstructure:"websocket_compression_mode"`
	WebsocketCompressionThreshold          int    `mapstructure:"websocket_compression_threshold"`
	WebsocketDevelopmentInsecureSkipVerify bool   `mapstructure:"websocket_development_insecure_skip_verify"`
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
	ServiceName                              string `mapstructure:"service_name"`
	Version                                  string `mapstructure:"version"`
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
	WebsocketBackpressureDropPolicy          string `mapstructure:"websocket_backpressure_drop_policy"`
	WebsocketSlowClientLatencyMs             int    `mapstructure:"websocket_slow_client_latency_ms"`
	WebsocketSlowClientDisconnectThresholdMs int    `mapstructure:"websocket_slow_client_disconnect_threshold_ms"`
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
	v.SetConfigName(getEnv("DAISI_WS_CONFIG_NAME", "config"))
	v.SetConfigType("yaml")
	v.AddConfigPath(getEnv("DAISI_WS_CONFIG_PATH", "./config"))
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
	client, cleanup2, err := RedisClientProvider(provider, domainLogger)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	sessionLockManager := SessionLockManagerProvider(client, domainLogger)
	killSwitchPubSubAdapter := KillSwitchPubSubAdapterProvider(client, domainLogger)
	routeRegistry := RouteRegistryProvider(client, domainLogger)
	connectionManager := ConnectionManagerProvider(domainLogger, provider, sessionLockManager, killSwitchPubSubAdapter, killSwitchPubSubAdapter, routeRegistry)
	grpcMessageHandler := GRPCMessageHandlerProvider(domainLogger, connectionManager)
	grpcServer, err := GRPCServerProvider(ctx, domainLogger, provider, grpcMessageHandler)
	if err != nil {
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	companyUserTokenGenerateHandler := GenerateTokenHandlerProvider(provider, domainLogger)
	adminUserTokenGenerateHandler := GenerateAdminTokenHandlerProvider(provider, domainLogger)
	tokenGenerationMiddleware := TokenGenerationAuthMiddlewareProvider(provider, domainLogger)
	tokenCacheStore := TokenCacheStoreProvider(client, domainLogger)
	adminTokenCacheStore := AdminTokenCacheStoreProvider(client, domainLogger)
	authService := AuthServiceProvider(domainLogger, provider, tokenCacheStore, adminTokenCacheStore)
	natsConsumer, cleanup3, err := NatsConsumerAdapterProvider(ctx, provider, domainLogger)
	if err != nil {
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	messageForwarder := MessageForwarderProvider(ctx, domainLogger, provider)
	handler := WebsocketHandlerProvider(domainLogger, provider, connectionManager, natsConsumer, routeRegistry, messageForwarder)
	router := WebsocketRouterProvider(domainLogger, provider, authService, handler)
	adminAuthMiddleware := AdminAuthMiddlewareProvider(authService, domainLogger)
	adminHandler := AdminWebsocketHandlerProvider(domainLogger, provider, connectionManager, natsConsumer)
	conn := NatsConnectionProvider(natsConsumer)
	app, cleanup4, err := NewApp(provider, domainLogger, serveMux, server, grpcServer, companyUserTokenGenerateHandler, adminUserTokenGenerateHandler, tokenGenerationMiddleware, router, connectionManager, natsConsumer, adminAuthMiddleware, adminHandler, conn, client)
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

## File: internal/bootstrap/app.go
```go
package bootstrap
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
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
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.logger.Info(r.Context(), "Health check endpoint hit")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"OK"}`)
	})
	a.httpServeMux.Handle("GET /health", middleware.RequestIDMiddleware(healthHandler))
	readyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.logger.Info(r.Context(), "Readiness check endpoint hit")
		w.Header().Set("Content-Type", "application/json")
		ready := true
		dependenciesStatus := make(map[string]string)
		if a.natsConn != nil {
			if a.natsConn.Status() == nats.CONNECTED {
				dependenciesStatus["nats"] = "connected"
			} else {
				dependenciesStatus["nats"] = "disconnected"
				ready = false
				a.logger.Warn(r.Context(), "Readiness check failed: NATS disconnected", "status", a.natsConn.Status().String())
			}
		} else {
			dependenciesStatus["nats"] = "not_configured"
			ready = false
			a.logger.Warn(r.Context(), "Readiness check failed: NATS client not configured in App struct")
		}
		if a.redisClient != nil {
			if err := a.redisClient.Ping(r.Context()).Err(); err == nil {
				dependenciesStatus["redis"] = "connected"
			} else {
				dependenciesStatus["redis"] = "disconnected"
				ready = false
				a.logger.Warn(r.Context(), "Readiness check failed: Redis ping failed", "error", err.Error())
			}
		} else {
			dependenciesStatus["redis"] = "not_configured"
			ready = false
			a.logger.Warn(r.Context(), "Readiness check failed: Redis client not configured in App struct")
		}
		if a.grpcServer != nil && a.configProvider.Get().Server.GRPCPort > 0 {
			grpcTarget := fmt.Sprintf("localhost:%d", a.configProvider.Get().Server.GRPCPort)
			conn, err := grpc.DialContext(r.Context(), grpcTarget, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
			if err != nil {
				dependenciesStatus["grpc"] = "dial_error"
				ready = false
				a.logger.Warn(r.Context(), "Readiness check failed: gRPC server dial error", "target", grpcTarget, "error", err.Error())
			} else {
				healthClient := grpc_health_v1.NewHealthClient(conn)
				healthResp, err := healthClient.Check(r.Context(), &grpc_health_v1.HealthCheckRequest{Service: ""}) // Check overall server health
				if err != nil {
					dependenciesStatus["grpc"] = "health_check_error"
					ready = false
					a.logger.Warn(r.Context(), "Readiness check failed: gRPC health check error", "target", grpcTarget, "error", err.Error())
				} else if healthResp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
					dependenciesStatus["grpc"] = "not_serving"
					ready = false
					a.logger.Warn(r.Context(), "Readiness check failed: gRPC server not serving", "target", grpcTarget, "status", healthResp.GetStatus().String())
				} else {
					dependenciesStatus["grpc"] = "serving"
				}
				conn.Close()
			}
		} else {
			dependenciesStatus["grpc"] = "not_configured_or_running"
			if a.configProvider.Get().Server.GRPCPort > 0 {
				ready = false
				a.logger.Warn(r.Context(), "Readiness check: gRPC server not configured or not running but GRPCPort > 0")
			}
		}
		response := struct {
			Status       string            `json:"status"`
			Dependencies map[string]string `json:"dependencies"`
		}{
			Dependencies: dependenciesStatus,
		}
		if ready {
			response.Status = "READY"
			w.WriteHeader(http.StatusOK)
		} else {
			response.Status = "NOT_READY"
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			a.logger.Error(r.Context(), "Failed to encode readiness response", "error", err)
		}
	})
	a.httpServeMux.Handle("GET /ready", middleware.RequestIDMiddleware(readyHandler))
	a.httpServeMux.Handle("GET /metrics", middleware.RequestIDMiddleware(promhttp.Handler()))
	a.logger.Info(ctx, "Prometheus metrics endpoint registered at /metrics")
	if a.wsRouter != nil {
		a.wsRouter.RegisterRoutes(ctx, a.httpServeMux)
	} else {
		a.logger.Warn(ctx, "WebSocket router is not initialized. WebSocket routes will not be available.")
	}
	if a.generateTokenHandler != nil && a.tokenGenerationMiddleware != nil {
		handlerToWrap := http.HandlerFunc(a.generateTokenHandler)
		finalGenerateTokenHandler := middleware.RequestIDMiddleware(a.tokenGenerationMiddleware(handlerToWrap))
		a.httpServeMux.Handle("POST /generate-token", finalGenerateTokenHandler)
		a.logger.Info(ctx, "/generate-token endpoint registered")
	} else {
		a.logger.Error(ctx, "GenerateTokenHandler or TokenGenerationMiddleware not initialized. /generate-token endpoint will not be available.")
	}
	if a.generateAdminTokenHandler != nil && a.tokenGenerationMiddleware != nil {
		adminHandlerToWrap := http.HandlerFunc(a.generateAdminTokenHandler)
		finalAdminGenerateTokenHandler := middleware.RequestIDMiddleware(a.tokenGenerationMiddleware(adminHandlerToWrap))
		a.httpServeMux.Handle("POST /admin/generate-token", finalAdminGenerateTokenHandler)
		a.logger.Info(ctx, "/admin/generate-token endpoint registered")
	} else {
		a.logger.Error(ctx, "GenerateAdminTokenHandler or TokenGenerationMiddleware not initialized. /admin/generate-token endpoint will not be available.")
	}
	if a.adminWsHandler != nil && a.adminAuthMiddleware != nil && a.configProvider != nil {
		apiKeyAuth := middleware.APIKeyAuthMiddleware(a.configProvider, a.logger)
		adminAuthedHandler := a.adminAuthMiddleware(a.adminWsHandler)
		chainedAdminHandler := apiKeyAuth(adminAuthedHandler)
		finalAdminWsHandler := middleware.RequestIDMiddleware(chainedAdminHandler)
		a.httpServeMux.Handle("GET /ws/admin", finalAdminWsHandler)
		a.logger.Info(ctx, "Admin WebSocket endpoint /ws/admin registered")
	} else {
		a.logger.Error(ctx, "AdminWsHandler, AdminAuthMiddleware, or ConfigProvider not initialized. /ws/admin endpoint will not be available.")
	}
	if a.grpcServer != nil {
		if err := a.grpcServer.Start(); err != nil {
			a.logger.Error(ctx, "Failed to start gRPC server", "error", err.Error())
		} else {
			a.logger.Info(ctx, "gRPC server started successfully.")
		}
	} else {
		a.logger.Warn(ctx, "gRPC server is not initialized. gRPC services will not be available.")
	}
	if a.connectionManager != nil {
		safego.Execute(ctx, a.logger, "ConnectionManagerKillSwitchListener", func() {
			a.connectionManager.StartKillSwitchListener(ctx)
		})
		safego.Execute(ctx, a.logger, "ConnectionManagerAdminKillSwitchListener", func() {
			a.connectionManager.StartAdminKillSwitchListener(ctx)
		})
		safego.Execute(ctx, a.logger, "ConnectionManagerResourceRenewalLoop", func() {
			a.connectionManager.StartResourceRenewalLoop(ctx)
		})
	} else {
		a.logger.Warn(ctx, "ConnectionManager not initialized. Session and route management features may be impaired.")
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
			a.logger.Info(context.Background(), "Closing all WebSocket connections gracefully...")
			a.connectionManager.GracefullyCloseAllConnections(domain.StatusGoingAway, "Server is shutting down")
			time.Sleep(1 * time.Second)
			a.connectionManager.StopKillSwitchListener()
			a.connectionManager.StopResourceRenewalLoop()
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
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	appgrpc "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc"
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
type CompanyUserTokenGenerateHandler http.HandlerFunc
type AdminUserTokenGenerateHandler http.HandlerFunc
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
	grpcServer                *appgrpc.Server
	generateTokenHandler      CompanyUserTokenGenerateHandler
	generateAdminTokenHandler AdminUserTokenGenerateHandler
	tokenGenerationMiddleware TokenGenerationMiddleware
	wsRouter                  *wsadapter.Router
	connectionManager         *application.ConnectionManager
	natsConsumerAdapter       domain.NatsConsumer
	adminAuthMiddleware       AdminAuthMiddleware
	adminWsHandler            *wsadapter.AdminHandler
	natsConn                  *nats.Conn
	redisClient               *redis.Client
}
func NewApp(
	cfgProvider config.Provider,
	appLogger domain.Logger,
	mux *http.ServeMux,
	server *http.Server,
	grpcSrv *appgrpc.Server,
	genTokenHandler CompanyUserTokenGenerateHandler,
	genAdminTokenHandler AdminUserTokenGenerateHandler,
	tokenGenMiddleware TokenGenerationMiddleware,
	wsRouter *wsadapter.Router,
	connManager *application.ConnectionManager,
	natsAdapter domain.NatsConsumer,
	adminAuthMid AdminAuthMiddleware,
	adminHandler *wsadapter.AdminHandler,
	natsConn *nats.Conn,
	redisClient *redis.Client,
) (*App, func(), error) {
	app := &App{
		configProvider:            cfgProvider,
		logger:                    appLogger,
		httpServeMux:              mux,
		httpServer:                server,
		grpcServer:                grpcSrv,
		generateTokenHandler:      genTokenHandler,
		generateAdminTokenHandler: genAdminTokenHandler,
		tokenGenerationMiddleware: tokenGenMiddleware,
		wsRouter:                  wsRouter,
		connectionManager:         connManager,
		natsConsumerAdapter:       natsAdapter,
		adminAuthMiddleware:       adminAuthMid,
		adminWsHandler:            adminHandler,
		natsConn:                  natsConn,
		redisClient:               redisClient,
	}
	cleanup := func() {
		app.logger.Info(context.Background(), "Running app cleanup...")
		if app.connectionManager != nil {
			app.connectionManager.StopKillSwitchListener()
			app.connectionManager.StopResourceRenewalLoop()
		}
		if app.grpcServer != nil {
			app.logger.Info(context.Background(), "Stopping gRPC server during app cleanup...")
			app.grpcServer.GracefulStop()
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
	appServerCfg := appCfg.App
	readTimeout := 10 * time.Second
	writeTimeout := 10 * time.Second
	idleTimeout := 60 * time.Second
	if appServerCfg.ReadTimeoutSeconds > 0 {
		readTimeout = time.Duration(appServerCfg.ReadTimeoutSeconds) * time.Second
	}
	if appServerCfg.WriteTimeoutSeconds > 0 {
		writeTimeout = time.Duration(appServerCfg.WriteTimeoutSeconds) * time.Second
	}
	if appServerCfg.IdleTimeoutSeconds > 0 {
		idleTimeout = time.Duration(appServerCfg.IdleTimeoutSeconds) * time.Second
	}
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", appCfg.Server.HTTPPort),
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
}
func GenerateTokenHandlerProvider(cfgProvider config.Provider, logger domain.Logger) CompanyUserTokenGenerateHandler {
	return CompanyUserTokenGenerateHandler(apphttp.GenerateTokenHandler(cfgProvider, logger))
}
func GenerateAdminTokenHandlerProvider(cfgProvider config.Provider, logger domain.Logger) AdminUserTokenGenerateHandler {
	return AdminUserTokenGenerateHandler(apphttp.GenerateAdminTokenHandler(cfgProvider, logger))
}
func TokenGenerationAuthMiddlewareProvider(cfgProvider config.Provider, logger domain.Logger) TokenGenerationMiddleware {
	return middleware.TokenGenerationAuthMiddleware(cfgProvider, logger)
}
func AdminAuthMiddlewareProvider(authService *application.AuthService, logger domain.Logger) AdminAuthMiddleware {
	return middleware.AdminAuthMiddleware(authService, logger)
}
func AdminWebsocketHandlerProvider(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter domain.NatsConsumer) *wsadapter.AdminHandler {
	return wsadapter.NewAdminHandler(logger, cfgProvider, connManager, natsAdapter)
}
func WebsocketHandlerProvider(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter domain.NatsConsumer, routeRegistry domain.RouteRegistry, messageForwarder domain.MessageForwarder) *wsadapter.Handler {
	return wsadapter.NewHandler(logger, cfgProvider, connManager, natsAdapter, routeRegistry, messageForwarder)
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
	routeRegistry domain.RouteRegistry,
) *application.ConnectionManager {
	return application.NewConnectionManager(logger, cfgProvider, sessionLocker, killSwitchPub, killSwitchSub, routeRegistry)
}
func TokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.TokenCacheStore {
	return appredis.NewTokenCacheAdapter(redisClient, logger)
}
func AdminTokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.AdminTokenCacheStore {
	return appredis.NewAdminTokenCacheAdapter(redisClient, logger)
}
func NatsConsumerAdapterProvider(ctx context.Context, cfgProvider config.Provider, appLogger domain.Logger) (domain.NatsConsumer, func(), error) {
	adapter, cleanup, err := appnats.NewConsumerAdapter(ctx, cfgProvider, appLogger)
	if err != nil {
		return nil, nil, err
	}
	return adapter, cleanup, nil
}
func RouteRegistryProvider(redisClient *redis.Client, logger domain.Logger) domain.RouteRegistry {
	return appredis.NewRouteRegistryAdapter(redisClient, logger)
}
func GRPCMessageHandlerProvider(logger domain.Logger, connManager *application.ConnectionManager) *application.GRPCMessageHandler {
	return application.NewGRPCMessageHandler(logger, connManager)
}
func GRPCServerProvider(appCtx context.Context, logger domain.Logger, cfgProvider config.Provider, grpcHandler *application.GRPCMessageHandler) (*appgrpc.Server, error) {
	return appgrpc.NewServer(appCtx, logger, cfgProvider, grpcHandler)
}
func NatsConnectionProvider(adapter domain.NatsConsumer) *nats.Conn {
	if adapter == nil {
		return nil
	}
	return adapter.NatsConn()
}
func MessageForwarderProvider(appCtx context.Context, logger domain.Logger, cfgProvider config.Provider) domain.MessageForwarder {
	return appgrpc.NewForwarderAdapter(appCtx, logger, cfgProvider)
}
var ProviderSet = wire.NewSet(
	ConfigProvider,
	LoggerProvider,
	HTTPServeMuxProvider,
	HTTPGracefulServerProvider,
	InitialZapLoggerProvider,
	GenerateTokenHandlerProvider,
	GenerateAdminTokenHandlerProvider,
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
	GRPCMessageHandlerProvider,
	GRPCServerProvider,
	AdminAuthMiddlewareProvider,
	AdminWebsocketHandlerProvider,
	AdminTokenCacheStoreProvider,
	RouteRegistryProvider,
	MessageForwarderProvider,
	NewApp,
	NatsConsumerAdapterProvider,
	NatsConnectionProvider,
)
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
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
	appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats"
	appredis "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/redis"
	"github.com/google/uuid"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
)
type Handler struct {
	logger           domain.Logger
	configProvider   config.Provider
	connManager      *application.ConnectionManager
	natsAdapter      domain.NatsConsumer
	routeRegistry    domain.RouteRegistry
	messageForwarder domain.MessageForwarder
}
func NewHandler(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter domain.NatsConsumer, routeRegistry domain.RouteRegistry, messageForwarder domain.MessageForwarder) *Handler {
	return &Handler{
		logger:           logger,
		configProvider:   cfgProvider,
		connManager:      connManager,
		natsAdapter:      natsAdapter,
		routeRegistry:    routeRegistry,
		messageForwarder: messageForwarder,
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
		metrics.IncrementSessionConflicts("user")
		domain.NewErrorResponse(domain.ErrSessionConflict, "Session already active elsewhere.", "").WriteJSON(w, http.StatusConflict)
		cancelWsConnLifetimeCtx() // Important: cancel before returning
		return
	}
	// If lock acquired, proceed to upgrade.
	sessionKey := rediskeys.SessionKey(authCtx.CompanyID, authCtx.AgentID, authCtx.UserID)
	h.logger.Info(r.Context(), "Session lock successfully acquired, proceeding to WebSocket upgrade", "sessionKey", sessionKey)
	var wrappedConn *Connection
	startTime := time.Now()
	appSpecificConfig := h.configProvider.Get().App
	opts := websocket.AcceptOptions{
		Subprotocols:       []string{"json.v1"},
		InsecureSkipVerify: appSpecificConfig.WebsocketDevelopmentInsecureSkipVerify,
		OnPongReceived: func(ctx context.Context, pongPayload []byte) {
			if wrappedConn != nil {
				h.logger.Debug(wrappedConn.Context(), "Pong received via AcceptOptions callback")
				wrappedConn.UpdateLastPongTime()
			}
		},
	}
	switch strings.ToLower(appSpecificConfig.WebsocketCompressionMode) {
	case "context_takeover":
		opts.CompressionMode = websocket.CompressionContextTakeover
		h.logger.Info(r.Context(), "WebSocket compression enabled: context_takeover")
	case "no_context_takeover":
		opts.CompressionMode = websocket.CompressionNoContextTakeover
		h.logger.Info(r.Context(), "WebSocket compression enabled: no_context_takeover")
	case "disabled":
		opts.CompressionMode = websocket.CompressionDisabled
		h.logger.Info(r.Context(), "WebSocket compression disabled by configuration.")
	default:
		opts.CompressionMode = websocket.CompressionDisabled
		h.logger.Warn(r.Context(), "Invalid WebSocket compression mode in config, defaulting to disabled.", "configured_mode", appSpecificConfig.WebsocketCompressionMode)
	}
	if opts.CompressionMode != websocket.CompressionDisabled {
		opts.CompressionThreshold = appSpecificConfig.WebsocketCompressionThreshold
		h.logger.Info(r.Context(), "WebSocket compression threshold set", "threshold_bytes", opts.CompressionThreshold)
	}
	if appSpecificConfig.WebsocketDevelopmentInsecureSkipVerify {
		opts.InsecureSkipVerify = true
		h.logger.Warn(r.Context(), "WebSocket InsecureSkipVerify ENABLED for development. DO NOT USE IN PRODUCTION.")
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
	metrics.IncrementConnectionsTotal()
	wrappedConn = NewConnection(wsConnLifetimeCtx, cancelWsConnLifetimeCtx, c, r.RemoteAddr, h.logger, h.configProvider, sessionKey)
	h.logger.Info(wrappedConn.Context(), "WebSocket connection established",
		"remoteAddr", wrappedConn.RemoteAddr(),
		"subprotocol", c.Subprotocol(),
		"company", authCtx.CompanyID,
		"agent", authCtx.AgentID,
		"user", authCtx.UserID,
		"sessionKey", sessionKey)
	h.connManager.RegisterConnection(sessionKey, wrappedConn, authCtx.CompanyID, authCtx.AgentID)
	defer func() {
		h.logger.Info(wrappedConn.Context(), "Connection management goroutine finished. Deregistering connection.", "sessionKey", sessionKey)
		duration := time.Since(startTime).Seconds()
		metrics.ObserveConnectionDuration(duration)
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
	readyMessage := domain.NewReadyMessage()
	if err := conn.WriteJSON(readyMessage); err != nil {
		h.logger.Error(connCtx, "Failed to send 'ready' message to client", "error", err.Error())
		return
	}
	metrics.IncrementMessagesSent(domain.MessageTypeReady)
	h.logger.Info(connCtx, "Sent 'ready' message to client")
	var generalNatsSubscription domain.NatsMessageSubscription
	var specificNatsSubscription domain.NatsMessageSubscription
	var currentSpecificChatID string
	generalChatEventsNatsHandler := func(msg *nats.Msg) {
		metrics.IncrementNatsMessagesReceived(msg.Subject)
		natsRequestID := msg.Header.Get(middleware.XRequestIDHeader)
		if natsRequestID == "" {
			natsRequestID = uuid.NewString()
		}
		msgCtx := context.WithValue(connCtx, contextkeys.RequestIDKey, natsRequestID)
		h.logger.Info(msgCtx, "Received general chat event from NATS", "subject", msg.Subject, "data_len", len(msg.Data))
		var eventPayload domain.EnrichedEventPayload
		if errUnmarshal := json.Unmarshal(msg.Data, &eventPayload); errUnmarshal != nil {
			h.logger.Error(msgCtx, "Failed to unmarshal general chat event payload", "subject", msg.Subject, "error", errUnmarshal.Error())
			return
		}
		wsMessage := domain.NewEventMessage(eventPayload)
		if errWrite := conn.WriteJSON(wsMessage); errWrite != nil {
			h.logger.Error(msgCtx, "Failed to forward general chat event to WebSocket client", "subject", msg.Subject, "event_id", eventPayload.EventID, "error", errWrite.Error())
			return
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeEvent)
		}
		_ = msg.Ack()
	}
	if h.natsAdapter != nil {
		var subErr error
		generalNatsSubscription, subErr = h.natsAdapter.SubscribeToChats(connCtx, companyID, agentID, generalChatEventsNatsHandler)
		if subErr != nil {
			h.logger.Error(connCtx, "Failed to subscribe to general NATS chats topic", "companyID", companyID, "agentID", agentID, "error", subErr.Error())
			errorMsg := domain.NewErrorResponse(domain.ErrSubscriptionFailure, "Could not subscribe to chat updates", subErr.Error())
			if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorMsg)); sendErr != nil {
				h.logger.Error(connCtx, "Failed to send NATS subscription error to client for general chats", "error", sendErr.Error())
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeError)
			}
		} else {
			h.logger.Info(connCtx, "Successfully subscribed to general NATS chats topic", "subject", generalNatsSubscription.Subject())
		}
	} else {
		h.logger.Warn(connCtx, "NATS adapter not available, cannot subscribe to general chat events.")
	}
	specificChatNatsMessageHandler := func(msg *nats.Msg) {
		metrics.IncrementNatsMessagesReceived(msg.Subject)
		natsRequestID := msg.Header.Get(middleware.XRequestIDHeader)
		if natsRequestID == "" {
			natsRequestID = uuid.NewString()
			h.logger.Debug(connCtx, "Generated new request_id for NATS message", "subject", msg.Subject, "new_request_id", natsRequestID)
		} else {
			h.logger.Debug(connCtx, "Using existing request_id from NATS message header", "subject", msg.Subject, "request_id", natsRequestID)
		}
		msgCtx := context.WithValue(connCtx, contextkeys.RequestIDKey, natsRequestID)
		msgCompanyID, msgAgentID, msgChatID, err := appnats.ParseNATSMessageSubject(msg.Subject)
		if err != nil {
			h.logger.Error(msgCtx, "Failed to parse NATS message subject", "subject", msg.Subject, "error", err.Error())
			return
		}
		currentPodID := h.configProvider.Get().Server.PodID
		if currentPodID == "" {
			h.logger.Error(connCtx, "Current PodID is not configured, cannot determine message ownership.", "subject", msg.Subject)
			return
		}
		ownerPodID, err := h.routeRegistry.GetOwningPodForMessageRoute(connCtx, msgCompanyID, msgAgentID, msgChatID)
		if err != nil {
			if errors.Is(err, appredis.ErrNoOwningPod) {
				h.logger.Warn(connCtx, "No owning pod found for message route in Redis, potential race or cleanup issue. NACKing message.", "subject", msg.Subject, "chat_id_from_subject", msgChatID)
				if nakErr := msg.Nak(); nakErr != nil {
					h.logger.Error(connCtx, "Failed to NACK NATS message for ErrNoOwningPod", "subject", msg.Subject, "error", nakErr.Error())
				}
				return
			} else {
				h.logger.Error(connCtx, "Failed to get owning pod for message route from Redis", "subject", msg.Subject, "error", err.Error())
				return
			}
		}
		var isOwner bool
		if ownerPodID == currentPodID {
			isOwner = true
		} else {
			isOwner = false
			if ownerPodID == "" {
				h.logger.Error(connCtx, "Internal logic inconsistency: ownerPodID is empty after GetOwningPodForMessageRoute succeeded. Assuming not owner.", "subject", msg.Subject)
			}
		}
		if isOwner {
			h.logger.Info(msgCtx, "Current pod IS THE OWNER of the message route. Delivering locally.", "subject", msg.Subject, "podID", currentPodID)
			var eventPayload domain.EnrichedEventPayload
			if errUnmarshal := json.Unmarshal(msg.Data, &eventPayload); errUnmarshal != nil {
				h.logger.Error(msgCtx, "Failed to unmarshal NATS message into EnrichedEventPayload (owner)",
					"subject", msg.Subject, "error", errUnmarshal.Error(), "raw_data", string(msg.Data))
				return
			}
			wsMessage := domain.NewEventMessage(eventPayload)
			if errWrite := conn.WriteJSON(wsMessage); errWrite != nil {
				h.logger.Error(msgCtx, "Failed to forward NATS message to WebSocket client (owner)",
					"subject", msg.Subject, "event_id", eventPayload.EventID, "error", errWrite.Error(),
				)
				return
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeEvent)
			}
		} else {
			h.logger.Info(msgCtx, "Current pod IS NOT THE OWNER of the message route. Attempting gRPC hop via MessageForwarder.",
				"subject", msg.Subject, "current_pod_id", currentPodID, "owner_pod_id", ownerPodID)
			if ownerPodID != "" { // Ensure there is a specific owner pod to forward to
				gprcTargetAddress := fmt.Sprintf("%s:%d", ownerPodID, h.configProvider.Get().Server.GRPCPort)
				var domainPayload domain.EnrichedEventPayload
				if errUnmarshal := json.Unmarshal(msg.Data, &domainPayload); errUnmarshal != nil {
					h.logger.Error(msgCtx, "Failed to unmarshal NATS message data for gRPC forwarding (MessageForwarder)", "subject", msg.Subject, "error", errUnmarshal.Error())
					return
				} else {
					if errFwd := h.messageForwarder.ForwardEvent(msgCtx, gprcTargetAddress, &domainPayload, msgCompanyID, msgAgentID, msgChatID, currentPodID); errFwd != nil {
						h.logger.Error(msgCtx, "Failed to forward event via MessageForwarder", "target_address", gprcTargetAddress, "event_id", domainPayload.EventID, "error", errFwd.Error())
						return
					} else {
						h.logger.Info(msgCtx, "Successfully initiated event forwarding via MessageForwarder", "target_address", gprcTargetAddress, "event_id", domainPayload.EventID)
					}
				}
			} else {
				h.logger.Warn(msgCtx, "No specific owner pod ID found for gRPC hop (MessageForwarder), message will not be forwarded.", "subject", msg.Subject)
			}
		}
		if ackErr := msg.Ack(); ackErr != nil {
			h.logger.Error(msgCtx, "Failed to ACK NATS message after processing", "subject", msg.Subject, "error", ackErr.Error())
		}
	}
	defer func() {
		if generalNatsSubscription != nil && generalNatsSubscription.IsValid() {
			h.logger.Info(connCtx, "Draining general NATS subscription on connection close", "subject", generalNatsSubscription.Subject())
			if unsubErr := generalNatsSubscription.Drain(); unsubErr != nil {
				h.logger.Error(connCtx, "Error draining general NATS subscription on close", "subject", generalNatsSubscription.Subject(), "error", unsubErr.Error())
			}
		}
		if specificNatsSubscription != nil && specificNatsSubscription.IsValid() {
			h.logger.Info(connCtx, "Draining specific NATS subscription on connection close", "subject", specificNatsSubscription.Subject(), "chatID", currentSpecificChatID)
			if unsubErr := specificNatsSubscription.Drain(); unsubErr != nil {
				h.logger.Error(connCtx, "Error draining specific NATS subscription on close", "subject", specificNatsSubscription.Subject(), "error", unsubErr.Error())
			}
		}
	}()
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
						errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to send ping", err.Error())
						conn.CloseWithError(errResp, "Ping failure")
						return
					}
					pingCancel()
					h.logger.Debug(connCtx, "Sent ping")
					if time.Since(conn.LastPongTime()) > pongWaitDuration {
						h.logger.Warn(connCtx, "Pong timeout. Closing connection.", "remoteAddr", conn.RemoteAddr(), "lastPong", conn.LastPongTime())
						errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No pong responses received within the configured duration.")
						conn.CloseWithError(errResp, "Pong timeout")
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
				errResp := domain.NewErrorResponse(domain.ErrInternal, "Pong timeout", "No message received within the configured timeout period.")
				conn.CloseWithError(errResp, "Pong timeout")
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
			var baseMsg domain.BaseMessage
			if err := json.Unmarshal(p, &baseMsg); err != nil {
				h.logger.Error(connCtx, "Failed to unmarshal incoming message into BaseMessage", "error", err.Error())
				errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid message format", err.Error())
				if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
					h.logger.Error(connCtx, "Failed to send error message to client for invalid format", "error", sendErr.Error())
				} else {
					metrics.IncrementMessagesSent(domain.MessageTypeError)
				}
				metrics.IncrementMessagesReceived("invalid_json")
				continue
			}
			metrics.IncrementMessagesReceived(baseMsg.Type)
			switch baseMsg.Type {
			case domain.MessageTypeSelectChat:
				h.logger.Info(connCtx, "Handling select_chat message type")
				newSub, newChatID, err := h.handleSelectChatMessage(connCtx, conn, companyID, agentID, userID, baseMsg.Payload, specificChatNatsMessageHandler, generalNatsSubscription, specificNatsSubscription, currentSpecificChatID)
				if err != nil {
					h.logger.Error(connCtx, "Error handling select_chat message", "error", err.Error())
					errResp := domain.NewErrorResponse(domain.ErrInternal, "Failed to process chat selection", err.Error())
					if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
						h.logger.Error(connCtx, "Failed to send error to client for select_chat failure", "error", sendErr.Error())
					} else {
						metrics.IncrementMessagesSent(domain.MessageTypeError)
					}
				} else {
					generalNatsSubscription = nil
					specificNatsSubscription = newSub
					currentSpecificChatID = newChatID
				}
			default:
				h.logger.Warn(connCtx, "Handling unknown message type", "type", baseMsg.Type)
				h.handleUnknownMessage(connCtx, conn, baseMsg)
			}
		} else if msgType == websocket.MessageBinary {
			h.logger.Info(connCtx, "Received binary message, currently unhandled.")
		}
	}
}
func (h *Handler) handleSelectChatMessage(
	connCtx context.Context,
	conn *Connection,
	companyID, agentID, userID string,
	payloadData interface{},
	specificChatNatsMsgHandler domain.NatsMessageHandler,
	currentGeneralSub domain.NatsMessageSubscription,
	currentSpecificSub domain.NatsMessageSubscription,
	currentSpecificSubChatID string,
) (domain.NatsMessageSubscription, string, error) {
	payloadMap, ok := payloadData.(map[string]interface{})
	if !ok {
		h.logger.Error(connCtx, "Invalid payload structure for select_chat after initial unmarshal", "type_received", fmt.Sprintf("%T", payloadData))
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload structure", "Expected a JSON object as payload.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for select_chat structure", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("invalid payload structure")
	}
	chatIDInterface, found := payloadMap["chat_id"]
	if !found {
		h.logger.Error(connCtx, "chat_id missing from select_chat payload map", "company", companyID, "agent", agentID, "user", userID)
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", "chat_id is missing.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for missing chat_id", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("chat_id missing from payload")
	}
	chatID, ok := chatIDInterface.(string)
	if !ok || chatID == "" {
		h.logger.Error(connCtx, "Invalid chat_id type or empty in select_chat payload", "type_received", fmt.Sprintf("%T", chatIDInterface), "value", chatIDInterface, "company", companyID, "agent", agentID, "user", userID)
		errorResponse := domain.NewErrorResponse(domain.ErrBadRequest, "Invalid select_chat payload", "chat_id must be a non-empty string.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for invalid chat_id type", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("invalid chat_id type or empty")
	}
	h.logger.Info(connCtx, "Client selected chat", "chat_id", chatID, "company", companyID, "agent", agentID, "user", userID)
	cfg := h.configProvider.Get()
	podID := cfg.Server.PodID
	routeTTL := time.Duration(cfg.App.RouteTTLSeconds) * time.Second
	if routeTTL <= 0 {
		routeTTL = 30 * time.Second
		h.logger.Warn(connCtx, "RouteTTLSeconds not configured or zero, using default 30s for message route registration", "newChatID", chatID)
	}
	if podID == "" {
		h.logger.Error(connCtx, "PodID is not configured. Cannot manage message routes.", "newChatID", chatID)
		errorResponse := domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Cannot process chat selection due to server misconfiguration.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for podID config error", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("podID is not configured")
	}
	routeReg := h.connManager.RouteRegistrar()
	if routeReg == nil {
		h.logger.Error(connCtx, "RouteRegistry is not available in ConnectionManager. Cannot manage message routes.", "newChatID", chatID)
		errorResponse := domain.NewErrorResponse(domain.ErrInternal, "Server error", "Cannot process chat selection due to server error.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for RouteRegistry nil error", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, conn.GetCurrentChatID(), fmt.Errorf("routeRegistry is nil")
	}
	oldChatID := conn.GetCurrentChatID()
	if oldChatID == chatID {
		h.logger.Info(connCtx, "Client selected the same chat_id, no changes to routes or NATS subscription needed.", "chatID", chatID)
		return currentSpecificSub, chatID, nil
	}
	if oldChatID != "" {
		h.logger.Info(connCtx, "Unregistering old message route", "oldChatID", oldChatID, "podID", podID)
		if err := routeReg.UnregisterMessageRoute(connCtx, companyID, agentID, oldChatID, podID); err != nil {
			h.logger.Error(connCtx, "Failed to unregister old message route",
				"oldChatID", oldChatID, "podID", podID, "error", err.Error(),
			)
		} else {
			h.logger.Info(connCtx, "Successfully unregistered old message route", "oldChatID", oldChatID)
		}
	}
	h.logger.Info(connCtx, "Registering new message route", "newChatID", chatID, "podID", podID, "ttl", routeTTL.String())
	if err := routeReg.RegisterMessageRoute(connCtx, companyID, agentID, chatID, podID, routeTTL); err != nil {
		h.logger.Error(connCtx, "Failed to register new message route",
			"newChatID", chatID, "podID", podID, "error", err.Error(),
		)
		errorResponse := domain.NewErrorResponse(domain.ErrInternal, "Failed to select chat", "Could not update message subscription.")
		if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
			h.logger.Error(connCtx, "Failed to send error message to client for new route registration failure", "error", sendErr.Error())
		} else {
			metrics.IncrementMessagesSent(domain.MessageTypeError)
		}
		return currentSpecificSub, oldChatID, fmt.Errorf("failed to register new message route: %w", err)
	}
	h.logger.Info(connCtx, "Successfully registered new message route", "newChatID", chatID)
	if currentGeneralSub != nil && currentGeneralSub.IsValid() {
		h.logger.Info(connCtx, "Draining general NATS chats subscription as a specific chat is being selected.", "subject", currentGeneralSub.Subject())
		if err := currentGeneralSub.Drain(); err != nil {
			h.logger.Error(connCtx, "Failed to drain general NATS chats subscription", "subject", currentGeneralSub.Subject(), "error", err.Error())
		}
	}
	if currentSpecificSub != nil && currentSpecificSub.IsValid() && currentSpecificSubChatID != "" && currentSpecificSubChatID != chatID { // Added IsValid check
		h.logger.Info(connCtx, "Draining previous NATS subscription for specific chat messages", "old_chat_id", currentSpecificSubChatID, "subject", currentSpecificSub.Subject())
		if err := currentSpecificSub.Drain(); err != nil {
			h.logger.Error(connCtx, "Failed to drain old specific NATS subscription", "old_chat_id", currentSpecificSubChatID, "subject", currentSpecificSub.Subject(), "error", err.Error())
		}
	}
	var newSpecificSubscription domain.NatsMessageSubscription
	var newSubErr error
	if h.natsAdapter != nil {
		h.logger.Info(connCtx, "Subscribing to NATS for new chat_id", "companyID", companyID, "agentID", agentID, "new_chat_id", chatID)
		newSpecificSubscription, newSubErr = h.natsAdapter.SubscribeToChatMessages(connCtx, companyID, agentID, chatID, specificChatNatsMsgHandler)
		if newSubErr != nil {
			h.logger.Error(connCtx, "Failed to subscribe to NATS for new chat messages",
				"companyID", companyID, "agentID", agentID, "new_chat_id", chatID, "error", newSubErr.Error(),
			)
			errorResponse := domain.NewErrorResponse(domain.ErrSubscriptionFailure, "Could not subscribe to new chat events.", newSubErr.Error())
			if sendErr := conn.WriteJSON(domain.NewErrorMessage(errorResponse)); sendErr != nil {
				h.logger.Error(connCtx, "Failed to send error to client for NATS sub failure", "error", sendErr.Error())
			} else {
				metrics.IncrementMessagesSent(domain.MessageTypeError)
			}
			conn.SetCurrentChatID(oldChatID)
			return currentSpecificSub, oldChatID, fmt.Errorf("failed to subscribe to NATS for chat %s: %w", chatID, newSubErr)
		}
		h.logger.Info(connCtx, "Successfully subscribed to NATS for new chat messages", "new_chat_id", chatID, "subject", newSpecificSubscription.Subject())
	} else {
		h.logger.Warn(connCtx, "NATS adapter not available, cannot subscribe to new chat messages.", "new_chat_id", chatID)
	}
	conn.SetCurrentChatID(chatID)
	h.logger.Info(connCtx, "Updated current chat ID for connection", "newChatID", chatID)
	return newSpecificSubscription, chatID, nil
}
func (h *Handler) handleUnknownMessage(connCtx context.Context, conn *Connection, baseMsg domain.BaseMessage) {
	h.logger.Warn(connCtx, "Received unhandled message type from client", "type", baseMsg.Type)
	errResp := domain.NewErrorResponse(domain.ErrBadRequest, "Unhandled message type", "Type: "+baseMsg.Type)
	if sendErr := conn.WriteJSON(domain.NewErrorMessage(errResp)); sendErr != nil {
		h.logger.Error(connCtx, "Failed to send error message to client for unhandled type", "error", sendErr.Error())
	} else {
		metrics.IncrementMessagesSent(domain.MessageTypeError)
	}
}
```
