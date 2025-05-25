# Daisi WebSocket Service - Developer Guide

This guide provides instructions and information for developers working on the Daisi WebSocket Service.

## Table of Contents

1.  [Setup Instructions](#1-setup-instructions)
2.  [Project Structure Overview](#2-project-structure-overview)
3.  [Development Workflow](#3-development-workflow)
4.  [Testing Approach](#4-testing-approach)
5.  [Benchmark Testing](#5-benchmark-testing)
6.  [Common Troubleshooting Steps](#6-common-troubleshooting-steps)

## 1. Setup Instructions

This section outlines how to set up the development environment.

### Prerequisites

*   **Go:** Version 1.23 or higher (as specified in `go.mod`).
*   **Docker & Docker Compose:** For running dependent services like NATS, Redis, and PostgreSQL, and for building/running the application in a containerized environment.
*   **Make:** For using Makefile shortcuts.
*   **Git:** For version control.
*   **(Optional) `golangci-lint`:** For linting Go code. Install from [https://golangci-lint.run/usage/install/](https://golangci-lint.run/usage/install/).
*   **Protocol Buffers Compiler:** For generating gRPC code from `.proto` files.

### Initial Setup

1.  **Clone the Repository:**
    ```bash
    git clone <repository_url>
    cd daisi-ws-service
    ```

2.  **Configuration:**
    *   Copy the example environment file (if available):
        ```bash
        cp .env.example .env
        ```
    *   The main configuration is in `config/config.yaml`. Environment variables will override these values.

3.  **Install Go Dependencies:**
    ```bash
    go mod tidy
    go mod download
    ```

4.  **Start Dependent Services (NATS, Redis, PostgreSQL):**
    The easiest way to start the required services is using Docker Compose:
    ```bash
    docker-compose up -d
    ```
    This will start NATS, Redis, and PostgreSQL with data persisted according to the Docker Compose configuration.

### Configuration Setup

The application uses `config/config.yaml` for its configuration. You'll need to update several placeholder values before running the service:

1.  **AES Encryption Keys:**
    The service requires two 32-byte (256-bit) AES keys for token encryption, which must be provided as 64-character hex strings:
    
    ```bash
    # Generate a hex-encoded 32-byte key for token encryption
    openssl rand -hex 32
    # Example output: 3a7bd3e2360a3d29eea436e864a1b8d5f2f5d5e4dba8ac39d465fc3488db3915
    
    # Generate a separate hex-encoded 32-byte key for admin token encryption
    openssl rand -hex 32
    # Example output: c8b7d5f83e8d4b3c9e2a7b6d5f4e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f
    ```
    
    Update `config.yaml` with these generated keys:
    ```yaml
    auth:
      token_aes_key: "3a7bd3e2360a3d29eea436e864a1b8d5f2f5d5e4dba8ac39d465fc3488db3915" 
      admin_token_aes_key: "c8b7d5f83e8d4b3c9e2a7b6d5f4e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f"
    ```

2.  **API Secret Tokens:**
    Generate secure random strings for the API tokens:
    
    ```bash
    # Generate a 32-character random string for the general secret token
    openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32
    
    # Generate another 32-character string for the admin secret token
    openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32
    ```
    
    Update `config.yaml` with these generated values:
    ```yaml
    auth:
      secret_token: "generated_general_secret_token_here"
      admin_secret_token: "generated_admin_secret_token_here"
    ```

3.  **Pod Identity:**
    Set a unique identifier for this service pod:
    ```yaml
    server:
      pod_id: "ws-service-pod-1" # For local development
    ```
    In Kubernetes environments, this is typically set via environment variables from the Downward API.

4.  **Service Connections:**
    Update the connection strings for NATS and Redis if needed:
    ```yaml
    nats:
      url: "nats://localhost:4222" # For local development
    
    redis:
      address: "localhost:6379" # For local development
    ```

5.  **SSL/TLS Settings:**
    For development with self-signed certificates, you might need to enable:
    ```yaml
    app:
      websocket_development_insecure_skip_verify: true # Only for local development!
    ```
    But ensure this is disabled in production environments.

6.  **Logging Level:**
    For development, you might want to set a more verbose logging level:
    ```yaml
    log:
      level: "debug" # Options: debug, info, warn, error
    ```

For production environments, it's recommended to use environment variables for sensitive values rather than storing them directly in the config.yaml file.

### Running the Application

*   **Locally using `go run`:**
    ```bash
    go run cmd/daisi-ws-service/main.go
    ```
    Ensure NATS, Redis, and other dependencies are accessible.

*   **Using Docker (after building):**
    First, build the Docker image:
    ```bash
    docker build -t daisi-ws-service:latest .
    ```
    Then, you can run it via Docker Compose.

### Useful Makefile Commands

If the project includes a Makefile, here are common commands that might be available:

*   `make build`: Builds the application's Docker image.
*   `make run`: Runs the application locally.
*   `make test`: Runs Go unit and integration tests.
*   `make lint`: Runs `golangci-lint`.
*   `make proto`: Generates Go code from Protocol Buffer definitions.
*   `make generate`: Runs `go generate ./...` (useful for tools like Wire).
*   `make clean`: Cleans up build artifacts.

#### Benchmark Commands

*   `make benchmark`: Runs all benchmark tests with profiling.
*   `make benchmark-auth`: Runs authentication benchmark tests only.
*   `make benchmark-conn`: Runs connection management benchmark tests only.
*   `make benchmark-msg`: Runs message processing benchmark tests only.
*   `make benchmark-integration`: Runs integration benchmark tests only.
*   `make benchmark-compare`: Compares current benchmark results with baseline.
*   `make benchmark-clean`: Cleans benchmark results and profiles.

## 2. Project Structure Overview

```
daisi-ws-service/
├── benchmarks/                        # Performance benchmark tests
│   ├── mocks/                         # Mock implementations for benchmarking
│   ├── utils/                         # Benchmark utilities and helpers
│   ├── auth_bench_test.go             # Authentication benchmarks
│   ├── connection_bench_test.go       # Connection management benchmarks
│   ├── integration_bench_test.go      # Integration scenario benchmarks
│   ├── message_bench_test.go          # Message processing benchmarks
│   └── session_bench_test.go          # Session management benchmarks
├── cmd/                               # Main application entrypoints
│   └── daisi-ws-service/
│       └── main.go                    # Application bootstrap and startup
├── config/                            # Configuration files
│   └── config.yaml                    # Default application configuration
├── deploy/                            # Deployment configuration
│   ├── grafana/                       # Grafana dashboards and configuration
│   └── postgres-init/                 # PostgreSQL initialization scripts
├── docs/                              # Project documentation
│   └── system_architecture.md         # Architecture documentation
├── internal/                          # Internal application code
│   ├── adapters/                      # Adapters for external services and frameworks
│   │   ├── config/                    # Configuration loading
│   │   ├── grpc/                      # gRPC client and server implementations
│   │   │   └── proto/                 # Protocol Buffer definitions
│   │   ├── http/                      # HTTP handlers
│   │   ├── logger/                    # Logging (Zap)
│   │   ├── metrics/                   # Metrics (Prometheus)
│   │   ├── middleware/                # HTTP and WebSocket middleware
│   │   ├── nats/                      # NATS client
│   │   ├── redis/                     # Redis adapters (session, routes, caching)
│   │   └── websocket/                 # WebSocket handlers
│   ├── application/                   # Core application logic, use cases, services
│   │   ├── auth_service.go            # Authentication services
│   │   ├── connection_manager.go      # WebSocket connection management
│   │   ├── connection_registry.go     # Connection tracking
│   │   ├── grpc_handler.go            # gRPC message handler
│   │   ├── kill_switch.go             # Session termination mechanism
│   │   ├── session_locking.go         # Session locking logic
│   │   └── session_renewal.go         # Session renewal logic
│   ├── bootstrap/                     # Dependency injection (Google Wire) and app initialization
│   │   ├── app.go                     # Application container
│   │   ├── providers.go               # DI providers
│   │   ├── wire_gen.go                # Generated Wire code
│   │   └── wire.go                    # Wire setup
│   └── domain/                        # Domain models, interfaces (ports), custom errors
│       ├── auth.go                    # Authentication models
│       ├── cache.go                   # Caching interfaces
│       ├── errors.go                  # Error definitions
│       ├── forwarder.go               # Message forwarding interfaces
│       ├── logger.go                  # Logger interface
│       ├── nats.go                    # NATS interfaces
│       ├── nats_payloads.go           # NATS message structures
│       ├── route_registry.go          # Route registry interfaces
│       ├── session.go                 # Session models
│       ├── websocket.go               # WebSocket interfaces
│       └── websocket_protocol.go      # WebSocket protocol definitions
├── pkg/                               # Public packages that could be used by other services
│   ├── contextkeys/                   # Context key definitions
│   ├── crypto/                        # Cryptography utilities
│   ├── rediskeys/                     # Redis key generation utilities
│   └── safego/                        # Safe goroutine execution
├── scripts/                           # Development and automation scripts
│   ├── run-benchmarks.sh              # Comprehensive benchmark runner
│   └── benchmark-compare.sh           # Benchmark comparison utility
├── docker-compose.yml                 # Docker Compose configuration
├── Dockerfile                         # Dockerfile for building the application image
├── go.mod                             # Go module definition
├── go.sum                             # Go module checksums
├── Makefile                           # Makefile for common development tasks
└── README.md                          # Project overview
```

## 3. Development Workflow

The typical development workflow involves:

1.  **Understand Requirements:** Clarify the feature or bug fix.
2.  **Branching:** Create a new Git branch for your changes.
3.  **Code Implementation:**
    *   Modify existing code or add new functionality, primarily within the `internal/` directory.
    *   **Domain Logic (`internal/domain`):** Define or update data structures, interfaces, and domain-specific errors.
    *   **Application Logic (`internal/application`):** Implement or modify business logic and services (like `ConnectionManager` or `AuthService`).
    *   **Adapters (`internal/adapters`):** If interacting with new external systems or changing how existing ones are used, update or add adapters.
    *   **Bootstrap (`internal/bootstrap`):** If adding new major components or changing dependencies, update the Wire provider sets. Run `make generate` to update `wire_gen.go`.
4.  **Configuration:** If new configuration parameters are needed, add them to `config/config.yaml` and update the configuration models in `internal/adapters/config/`.
5.  **Testing:**
    *   Write unit tests for new logic (place `_test.go` files alongside the code being tested).
    *   Ensure tests cover both happy paths and error conditions.
    *   Run tests using `go test ./...`.
    *   For performance-critical changes, run relevant benchmarks: `make benchmark-auth`, `make benchmark-conn`, etc.
    *   If adding new components, consider adding corresponding benchmarks in the `benchmarks/` directory.
6.  **Protocol Buffers:** If modifying gRPC interfaces:
    *   Update the `.proto` files in `internal/adapters/grpc/proto/`.
    *   Run the protobuf compiler to generate updated Go code.
7.  **Running Locally:**
    *   Use Docker Compose to ensure NATS/Redis are running.
    *   Run the application using `go run cmd/daisi-ws-service/main.go` or via Docker.
    *   Test WebSocket functionality using tools like `websocat` or browser-based WebSocket clients.
8.  **Commit and Push:** Commit your changes with clear messages and push to the remote repository.
9.  **Pull Request:** Create a pull request for review.

### Key Development Considerations

*   **WebSocket Connection Handling:**
    *   WebSocket connections are long-lived and require careful management.
    *   Test connection establishment, message handling, and graceful disconnection.
    *   Consider rate limits and maximum concurrent connection thresholds.

*   **Session Management:**
    *   The service enforces exclusive sessions per user across multiple pods.
    *   Test both normal authentication flows and session migration scenarios.

*   **Message Routing:**
    *   Changes to the routing system should maintain backward compatibility with existing clients.
    *   Test routing between pods, especially when adding new message types or fields.

*   **Authentication:**
    *   Token generation and validation are security-critical components.
    *   Test token expiration, validation, and caching thoroughly.

*   **Circuit Breakers and Resilience:**
    *   Changes affecting error handling should maintain the system's resilience features.
    *   Test how the system behaves during partial outages (e.g., Redis unavailable).

## 4. Testing Approach

The project employs a combination of unit and integration tests.

### Unit Tests

*   **Location:** Reside in `_test.go` files alongside the code they are testing (e.g., `internal/application/auth_service_test.go`).
*   **Purpose:** To test individual functions, methods, or small units of logic in isolation.
*   **Tools:** Standard Go `testing` package, possibly with `testify/assert` and `testify/mock` for assertions and mocking dependencies.
*   **Execution:** `go test ./internal/...`

### Integration Tests

*   **Purpose:** To test the interaction between different components of the service and with external dependencies like NATS, Redis, and gRPC.
*   **Tools:**
    *   Standard Go `testing` package.
    *   Mock implementations of interfaces for controlled testing.
    *   Dockerized dependencies for environment isolation.
*   **Areas to Cover:**
    *   WebSocket connection establishment and maintenance.
    *   Session locking and migration between pods.
    *   Message routing and delivery across pods.
    *   Token authentication and caching.

### Testing WebSockets

*   **Tools:**
    *   `websocat` for command-line WebSocket testing.
    *   Browser-based WebSocket clients for interactive testing.
    *   Custom test clients for automated testing.
*   **Key Scenarios:**
    *   Connection with valid and invalid tokens.
    *   Message reception from NATS events.
    *   Chat selection and routing.
    *   Connection migration via kill switch.
    *   Reconnection handling.

### Running Tests

*   **All tests:**
    ```bash
    go test ./...
    ```
*   **Specific package tests:**
    ```bash
    go test gitlab.com/timkado/api/daisi-ws-service/internal/application -v
    ```
*   **Test Coverage:**
    ```bash
    go test -cover ./...
    ```
    For a detailed HTML coverage report:
    ```bash
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    ```

## 5. Benchmark Testing

The service includes a comprehensive benchmark suite that measures performance across all major components. This section covers how to run, interpret, and troubleshoot benchmark tests.

### Benchmark Overview

The benchmark suite provides performance testing for:

- **Authentication**: Token validation, cache performance, concurrent access
- **Connection Management**: Registration, deregistration, lifecycle, memory usage
- **Message Processing**: NATS processing, WebSocket broadcasting, client routing
- **Session Management**: Locks, route registry, kill switch, conflict resolution
- **Integration Scenarios**: End-to-end flows, high-load testing, memory pressure

### Running Benchmarks

#### Using Makefile (Recommended)

The project includes convenient Makefile targets for running benchmarks:

```bash
# Run all benchmarks with profiling
make benchmark

# Run specific benchmark categories
make benchmark-auth          # Authentication benchmarks only
make benchmark-conn          # Connection management benchmarks only  
make benchmark-msg           # Message processing benchmarks only
make benchmark-integration   # Integration benchmarks only

# Compare with baseline results
make benchmark-compare

# Clean benchmark results
make benchmark-clean
```

#### Manual Execution

For more control over benchmark execution:

```bash
# Run all benchmarks
go test -bench=. ./benchmarks/

# Run specific benchmarks with custom settings
go test -bench=BenchmarkUserTokenValidation -benchtime=10s -count=3 ./benchmarks/

# Run with profiling
go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof ./benchmarks/

# Run integration benchmarks only
go test -bench="BenchmarkFullUserFlow|BenchmarkMessageFlow" ./benchmarks/

# Run with short benchmark time for quick testing
go test -bench=. -benchtime=1s ./benchmarks/
```

#### Benchmark Parameters

Common benchmark flags:

- `-bench=<pattern>`: Run benchmarks matching the pattern
- `-benchtime=<duration>`: Run each benchmark for specified duration (e.g., `5s`, `10s`)
- `-count=<n>`: Run each benchmark n times for statistical reliability
- `-cpuprofile=<file>`: Generate CPU profiling data
- `-memprofile=<file>`: Generate memory profiling data
- `-benchmem`: Include memory allocation statistics

### Interpreting Results

#### Sample Output

```
BenchmarkUserTokenValidation/ValidToken-10                491000               701.3 ns/op
BenchmarkFullUserFlow/SingleUserFlow-10                    68467             16549 ns/op
BenchmarkMessageFlow/SingleMessageFlow-10                 108180              4662 ns/op
BenchmarkHighLoadScenario/HighConcurrencyLoad-10              43          10452520 ns/op
```

#### Understanding Metrics

- **First number** (e.g., `491000`): Number of iterations run
- **Second number** (e.g., `701.3 ns/op`): Nanoseconds per operation
- **-10**: Number of CPU cores used (GOMAXPROCS)

#### Performance Baselines

Expected performance ranges based on benchmark results:

```yaml
Authentication:
  token_validation: "500-1000 ns/op"    # 1M+ ops/sec
  cache_hit_ratio: "86-93%"             # High cache efficiency

Message Processing:
  single_message: "4000-7000 ns/op"     # 145-250K messages/sec
  bulk_processing: "2500-6000 ns/op"    # 167-400K messages/sec

Connection Management:
  registration: "3000-6000 ns/op"       # 167-333K registrations/sec
  full_lifecycle: "5000-7000 ns/op"     # 143-200K lifecycles/sec

Integration Flows:
  user_flow: "15000-35000 ns/op"        # 29-67K flows/sec
  session_conflict: "20000-30000 ns/op" # 33-50K conflicts/sec

High Load:
  concurrent_1000_users: "~10ms/op"     # 100 full flows/sec
  memory_5000_conns: "~11ms/op"         # Memory pressure test
```

### Profiling and Analysis

#### Generating Profiles

```bash
# Generate CPU and memory profiles
go test -bench=BenchmarkFullUserFlow -cpuprofile=cpu.prof -memprofile=mem.prof ./benchmarks/

# Analyze CPU profile
go tool pprof cpu.prof
# Interactive commands in pprof:
# top10          - Show top 10 functions by CPU usage
# list <func>    - Show source code for function
# web           - Generate SVG call graph (requires graphviz)

# Analyze memory profile
go tool pprof mem.prof
# Common commands:
# top10 -cum     - Show top 10 by cumulative allocation
# list <func>    - Show memory allocations in function
```

#### Profile Analysis Tips

1. **CPU Hotspots**: Look for functions consuming >5% of CPU time
2. **Memory Leaks**: Check for unexpectedly high allocations
3. **Goroutine Bottlenecks**: Use `-blockprofile` to find blocking operations
4. **Comparison**: Compare profiles before/after optimization changes

### Performance Regression Testing

#### Establishing Baselines

```bash
# Run benchmarks and save baseline
make benchmark > baseline.txt

# Compare current performance against baseline
make benchmark > current.txt
./scripts/benchmark-compare.sh baseline.txt current.txt
```

#### Regression Thresholds

Watch for performance degradation:

- **>20% slower**: Investigate immediately
- **>10% slower**: Review and monitor
- **>5% slower**: Acceptable for most changes
- **Faster**: Potential improvement (verify correctness)

### Benchmark Development

#### Adding New Benchmarks

1. **Create benchmark function**:
```go
func BenchmarkNewFeature(b *testing.B) {
    // Setup
    service := setupTestService()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        // Code to benchmark
        result := service.ProcessSomething()
        if result == nil {
            b.Fatal("unexpected nil result")
        }
    }
}
```

2. **Follow naming conventions**:
   - Use `Benchmark` prefix
   - Group related benchmarks with sub-tests
   - Include scale information in names (e.g., `Scale_100`)

3. **Best practices**:
   - Use `b.ResetTimer()` after setup
   - Avoid allocations in benchmark loop when measuring specific operations
   - Use `b.StopTimer()` and `b.StartTimer()` to exclude cleanup
   - Store results to prevent compiler optimization

### Continuous Integration

#### Automated Benchmarking

Example CI configuration for benchmark regression testing:

```yaml
benchmark:
  stage: test
  script:
    - make benchmark > current_benchmark.txt
    - ./scripts/benchmark-compare.sh baseline_benchmark.txt current_benchmark.txt
  artifacts:
    reports:
      performance: current_benchmark.txt
  only:
    - merge_requests
    - main
```

#### Performance Monitoring

Set up alerts for benchmark regressions:

```yaml
alerts:
  - name: "benchmark_regression"
    condition: "performance_degradation > 10%"
    action: "notify_team"
  - name: "benchmark_failure"
    condition: "benchmark_execution_failed"
    action: "block_deployment"
```

### Troubleshooting Benchmarks

#### Common Issues

1. **Inconsistent Results**:
   - Increase `-benchtime` for more stable results
   - Use `-count=5` to run multiple times
   - Close other applications that might affect CPU/memory

2. **Benchmark Failures**:
   - Check if dependencies (Redis, NATS) are running
   - Verify configuration keys are properly set
   - Ensure sufficient system resources

3. **Memory Issues**:
   - Monitor system memory usage during benchmarks
   - Check for goroutine leaks with `runtime.NumGoroutine()`
   - Use memory profiling to identify allocation hotspots

4. **Slow Execution**:
   - High load benchmarks can take several minutes
   - Use shorter `-benchtime` for development
   - Consider running subsets with specific `-bench` patterns

#### Debug Commands

```bash
# Check benchmark compilation
go test -c ./benchmarks/

# Run with verbose output
go test -bench=. -v ./benchmarks/

# Run single benchmark for debugging
go test -bench=BenchmarkUserTokenValidation/ValidToken -count=1 ./benchmarks/

# Check system resources during benchmark
htop  # Monitor CPU/memory usage
```

### Performance Optimization Workflow

1. **Identify Bottlenecks**: Run profiling to find performance hotspots
2. **Create Focused Benchmarks**: Write specific benchmarks for the slow components
3. **Optimize Implementation**: Make targeted improvements
4. **Validate Changes**: Re-run benchmarks to measure improvement
5. **Regression Test**: Ensure other components aren't negatively affected
6. **Document Results**: Update performance baselines and documentation

## 6. Common Troubleshooting Steps

*   **WebSocket Connection Issues:**
    *   **Check Client-Side:** Ensure the client is using the correct WebSocket URL, token format, and protocol.
    *   **Verify TLS:** If using WSS (secure WebSocket), check certificate issues.
    *   **Authentication:** Check token validity and formatting.
    *   **Network:** Ensure there's no network/firewall blocking the WebSocket connection.
    *   **Server Logs:** Look for authentication failures or connection errors.

*   **Authentication Failures:**
    *   **Token Format:** Ensure tokens are correctly formatted and not expired.
    *   **Encryption Keys:** Verify the service has the correct AES encryption keys configured.
    *   **Redis Connectivity:** Check if token caching is failing due to Redis issues.

*   **Message Routing Issues:**
    *   **Route Registration:** Ensure routes are being correctly registered in Redis.
    *   **Redis Connectivity:** Check for Redis connection issues.
    *   **Pod Communication:** Verify gRPC communication between pods is working.
    *   **Check Logs:** Look for errors related to message forwarding or route lookup.

*   **Session Locking Problems:**
    *   **Redis Availability:** Verify Redis is accessible and operational.
    *   **Lock Keys:** Check if session locks have the expected format and TTL.
    *   **Kill Switch:** For migration issues, check if kill switch messages are being published/received.

*   **Performance Problems:**
    *   **Connection Count:** Monitor the number of active WebSocket connections.
    *   **Message Volume:** Check the rate of messages being processed.
    *   **Redis Operations:** Look for slow Redis operations in the logs.
    *   **Memory Usage:** Monitor for memory leaks, especially with long-lived connections.
    *   **Goroutines:** Check for goroutine leaks using `runtime.NumGoroutine()`.

*   **Application Startup Issues:**
    *   **Configuration:** Verify configuration values in `config.yaml` and environment variables.
    *   **Dependencies:** Ensure all required services (NATS, Redis) are available.
    *   **Port Conflicts:** Check if the required ports are already in use.
    *   **Permissions:** Verify the process has the necessary permissions for file access and network operations.

*   **Error Diagnostic Tips:**
    *   **Increase Log Level:** Temporarily set log level to `debug` for more detailed logs.
    *   **Isolate Components:** Test individual components to narrow down the issue.
    *   **Check Metrics:** Review Prometheus metrics for insights on system behavior.
    *   **Review Recent Changes:** Issues often correlate with recent code or configuration changes.

Always refer to the application logs as the first step in troubleshooting. The structured logging (via Zap) provides contextual information that can help pinpoint issues. 