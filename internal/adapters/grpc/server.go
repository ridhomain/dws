package grpc

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	// TODO: Add import for reflection: "google.golang.org/grpc/reflection"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	pb "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc/proto"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)

// Server wraps the gRPC server and its dependencies.
type Server struct {
	gsrv        *grpc.Server
	logger      domain.Logger
	cfgProvider config.Provider
	appCtx      context.Context // Renamed from srvCtx for clarity, this is the server's own lifecycle context derived from app context
	cancelCtx   context.CancelFunc
}

// NewServer creates a new gRPC server instance.
func NewServer(appCtx context.Context, logger domain.Logger, cfgProvider config.Provider, grpcHandler *application.GRPCMessageHandler) (*Server, error) {
	opts := []grpc.ServerOption{} // Start with no credentials (insecure)

	gsrv := grpc.NewServer(opts...)
	pb.RegisterMessageForwardingServiceServer(gsrv, grpcHandler)

	// TODO: Enable reflection only for development/debug builds based on config
	// if cfgProvider.Get().App.EnableGRPCReflection { reflection.Register(gsrv) }

	// Create a new context that can be cancelled independently for this server's lifecycle,
	// but is derived from the main application context.
	serverLifecycleCtx, serverLifecycleCancel := context.WithCancel(appCtx)

	return &Server{
		gsrv:        gsrv,
		logger:      logger,
		cfgProvider: cfgProvider,
		appCtx:      serverLifecycleCtx,
		cancelCtx:   serverLifecycleCancel,
	}, nil
}

// Start starts the gRPC server in a new goroutine.
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
		// If Serve returns, it means server stopped. Ensure its context is cancelled.
		s.logger.Info(s.appCtx, "gRPC server Serve() returned. Ensuring context is cancelled.")
		s.cancelCtx()
	})

	// Goroutine to handle shutdown when the server's context (s.appCtx) is done.
	safego.Execute(s.appCtx, s.logger, "GRPCServerContextWatcher", func() {
		<-s.appCtx.Done() // Wait for the server's lifecycle context to be cancelled
		s.logger.Info(context.Background(), "gRPC server context done (e.g. from app shutdown), initiating graceful stop...")
		s.gsrv.GracefulStop() // GracefulStop will wait for requests to finish.
		s.logger.Info(context.Background(), "gRPC server gracefully stopped after context cancellation.")
	})

	return nil
}

// GracefulStop is typically called when the application is shutting down.
// It relies on the server's internal context (s.appCtx) being cancelled.
func (s *Server) GracefulStop() {
	s.logger.Info(s.appCtx, "GracefulStop called for gRPC server. Cancelling its lifecycle context to trigger stop.")
	s.cancelCtx() // This will trigger the GRPCServerContextWatcher goroutine to call gsrv.GracefulStop()
}
