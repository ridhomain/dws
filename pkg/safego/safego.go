package safego

import (
	"context"
	"fmt"
	"runtime/debug"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// Execute runs the given function in a new goroutine.
// It recovers from any panics within the goroutine, logs them with the provided logger and a descriptive name,
// and includes a stack trace.
func Execute(ctx context.Context, logger domain.Logger, goroutineName string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Create a new context if the original one is done, to ensure logging still works.
				logCtx := ctx
				if ctx.Err() != nil {
					logCtx = context.Background()
				}
				logger.Error(logCtx, fmt.Sprintf("Panic recovered in goroutine: %s", goroutineName),
					"panic_info", fmt.Sprintf("%v", r), // Ensure panic info is well-formatted string
					"stacktrace", string(debug.Stack()),
				)
			}
		}()
		fn()
	}()
}
