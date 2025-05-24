package domain

import (
	"context"
)

// Logger defines the interface for logging within the application.
// Implementations will handle structured logging (e.g., JSON with Zap).
// All logging methods should accept a context.Context as the first argument
// to enable context-aware logging (e.g., including request IDs).
// The variadic `fields` argument allows for structured key-value pairs.
type Logger interface {
	Debug(ctx context.Context, msg string, fields ...any) // Using `any` for fields to be Zap-agnostic at interface level
	Info(ctx context.Context, msg string, fields ...any)
	Warn(ctx context.Context, msg string, fields ...any)
	Error(ctx context.Context, msg string, fields ...any)
	Fatal(ctx context.Context, msg string, fields ...any) // Fatal will call os.Exit(1) after logging

	// With creates a child logger with the provided structured context fields.
	With(fields ...any) Logger
}
