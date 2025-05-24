package logger

import (
	"context"
	"os"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config" // Assuming this is the correct path
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ZapAdapter implements the domain.Logger interface using Zap.
type ZapAdapter struct {
	logger *zap.Logger
}

// NewZapAdapter creates a new ZapAdapter.
// It configures Zap based on the provided application configuration.
func NewZapAdapter(cfgProvider config.Provider, serviceName string) (domain.Logger, error) {
	appConfig := cfgProvider.Get()
	logLevel := appConfig.Log.Level // Get log level from config

	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(logLevel)); err != nil {
		zapLevel = zapcore.InfoLevel // Default to InfoLevel if parsing fails
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
		EncodeTime:     zapcore.RFC3339NanoTimeEncoder, // UTC RFC3339Nano: 2025-05-21T10:30:05.123456789Z
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Configure console output for different levels
	// Errors, Fatals to stderr; Info, Debug, Warn to stdout
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

	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel)) // Add stacktrace for ErrorLevel and above

	// Add service_name as a static field to all logs from this logger instance
	zapLogger = zapLogger.With(zap.String("service", serviceName))

	return &ZapAdapter{logger: zapLogger}, nil
}

func (za *ZapAdapter) extractFieldsFromContext(ctx context.Context, additionalFields []any) []zap.Field {
	fields := make([]zap.Field, 0, len(additionalFields)/2+5) // Pre-allocate space

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
			// Odd number of fields, log the last one as a standalone value
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
	// Fatal should always log, regardless of core enablement check for other levels
	fields := za.extractFieldsFromContext(ctx, args)
	za.logger.Fatal(msg, fields...) // Zap's Fatal logs and then calls os.Exit(1)
}

func (za *ZapAdapter) With(args ...any) domain.Logger {
	// Convert args to zap.Field. This is a bit tricky because domain.Logger.With uses `...any`
	// while zap.Logger.With expects `...zap.Field`.
	// For simplicity here, we'll assume args are already zap.Field or convertible pairs.
	// A more robust implementation might inspect types or require specific formatting.
	zapFields := make([]zap.Field, 0, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			key, okKey := args[i].(string)
			val := args[i+1]
			if okKey {
				zapFields = append(zapFields, zap.Any(key, val))
			} else {
				// fallback if not string key - might log an error or skip
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
