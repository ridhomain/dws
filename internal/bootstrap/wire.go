//go:build wireinject
// +build wireinject

//go:generate wire

package bootstrap

import (
	"context"

	"github.com/google/wire"
)

// InitializeApp creates and initializes a new application instance with all its dependencies.
// It requires a serviceName to be passed in for logger configuration.
// Wire will use the providers in ProviderSet and the NewApp function to build the *App.
// The cleanup function returned can be used to sync loggers or close other resources.
func InitializeApp(ctx context.Context, serviceName ServiceName) (*App, func(), error) {
	wire.Build(ProviderSet, NewApp)
	return nil, nil, nil // Wire will replace this with the actual implementation
}
