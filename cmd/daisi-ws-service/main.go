package main

import (
	"context"
	"fmt"
	"os"

	"gitlab.com/timkado/api/daisi-ws-service/internal/bootstrap"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	// No longer directly using zap or other specific adapter packages here,
	// as they are handled by the bootstrap package and Wire.
)

func main() {
	// Create a root context for the application.
	// This context can be enhanced with initial values if necessary.
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.RequestIDKey, "app-main") // Example request ID for main flow

	// Initialize the application using the Wire-generated injector.
	// The serviceName is passed here; it could also be derived from initial config loading if complex.
	// The InitializeApp function now likely only takes context, based on linter errors and Wire output.
	app, cleanup, err := bootstrap.InitializeApp(ctx)
	if err != nil {
		// A very basic log if bootstrap fails, as the main logger isn't available.
		fmt.Printf("Failed to initialize application: %v\n", err)
		os.Exit(1)
	}
	// Defer the cleanup function to ensure resources are released on exit.
	// This typically includes syncing loggers.
	defer cleanup()

	// Run the application.
	// The Run method in App struct now handles server start and graceful shutdown.
	if err := app.Run(ctx); err != nil {
		// The app.Run() method should use its injected logger for errors.
		// This is a fallback print if something goes catastrophically wrong after Run() returns an error.
		fmt.Printf("Application run failed: %v\n", err)
		os.Exit(1)
	}

	// Application has completed its run (typically after shutdown signal).
	// The logger inside app.Run() would have logged shutdown messages.
	fmt.Println("Application exited gracefully.")
}
