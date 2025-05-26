.DEFAULT_GOAL := help

# Variables
DOCKER_COMPOSE = docker-compose
SERVICE_NAME = daisi-ws-service
GO_FILES = $(shell find . -name '*.go' -not -path "./vendor/*")
VERSION = "latest"

.PHONY: help
help:
	@echo "Makefile for daisi-ws-service"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build the Docker image for the service (typically tagged as latest by Docker Compose)."
	@echo "  make build_hardcoded_tag Build Docker image with the tag defined by HARDCODED_TAG in this Makefile."
	@echo "  make up             Start all services in detached mode (daisi-ws-service, nats, redis)."
	@echo "  make down           Stop and remove all services."
	@echo "  make logs           Tail logs from the daisi-ws-service container."
	@echo "  make logs-all       Tail logs from all services."
	@echo "  make ps             Show the status of running services."
	@echo "  make restart        Restart the daisi-ws-service container."
	@echo "  make shell          Open a shell into the daisi-ws-service container."
	@echo "  make clean          Stop and remove all services, including volumes."
	@echo "  make lint           Run Go linter (placeholder - customize with your linter)."
	@echo "  make test           Run Go tests (placeholder - customize with your test command)."
	@echo "  make proto          Generate Go code from Protocol Buffer definitions."
	@echo "  make wire           Run Wire to generate dependency injection code."
	@echo "  make tidy           Run go mod tidy."
	@echo "  make format         Run go fmt on all Go files."
	@echo "  make benchmark      Run all benchmark tests with profiling."
	@echo "  make benchmark-auth Run authentication benchmark tests only."
	@echo "  make benchmark-conn Run connection management benchmark tests only."
	@echo "  make benchmark-msg  Run message processing benchmark tests only."
	@echo "  make benchmark-integration Run integration benchmark tests only."
	@echo "  make benchmark-compare Compare current benchmark results with baseline."
	@echo ""

.PHONY: build
build:
	@echo "Building Docker image for $(SERVICE_NAME)..."
	$(DOCKER_COMPOSE) build $(SERVICE_NAME)

.PHONY: build_tag
build_tag:
	@echo "Building Docker image for $(SERVICE_NAME) with tag $(VERSION)..."
	docker build -t daisi/$(SERVICE_NAME):$(VERSION) .

.PHONY: up
up:
	@echo "Starting all services (daisi-ws-service, nats, redis)..."
	$(DOCKER_COMPOSE) up -d

.PHONY: down
down:
	@echo "Stopping all services..."
	$(DOCKER_COMPOSE) down

.PHONY: logs
logs:
	@echo "Tailing logs for $(SERVICE_NAME)..."
	$(DOCKER_COMPOSE) logs -f $(SERVICE_NAME)

.PHONY: logs-all
logs-all:
	@echo "Tailing logs for all services..."
	$(DOCKER_COMPOSE) logs -f

.PHONY: ps
ps:
	@echo "Status of services:"
	$(DOCKER_COMPOSE) ps

.PHONY: restart
restart:
	@echo "Restarting $(SERVICE_NAME)..."
	$(DOCKER_COMPOSE) restart $(SERVICE_NAME)

.PHONY: shell
shell:
	@echo "Opening shell into $(SERVICE_NAME) container..."
	$(DOCKER_COMPOSE) exec $(SERVICE_NAME) /bin/sh

.PHONY: clean
clean:
	@echo "Stopping and removing all services and volumes..."
	$(DOCKER_COMPOSE) down -v --remove-orphans

.PHONY: lint
lint:
	@echo "Running linter (placeholder)..."
	# Add your Go linting command here, e.g.:
	# golangci-lint run ./...
	@echo "Please configure your Go linter command in the Makefile."

.PHONY: test
test:
	@echo "Running tests (placeholder)..."
	# Add your Go test command here, e.g.:
	# go test -v ./...
	@echo "Please configure your Go test command in the Makefile."

.PHONY: proto
proto:
	@echo "Generating Go code from Protocol Buffers..."
	@# Ensure you have protoc, protoc-gen-go, and protoc-gen-go-grpc installed and in your PATH.
	@# Adjust paths and options as necessary for your project structure.
	@if [ -d "internal/adapters/grpc/proto" ]; then \
		protoc --proto_path=internal/adapters/grpc/proto \
		       --go_out=internal/adapters/grpc/proto --go_opt=paths=source_relative \
		       --go-grpc_out=internal/adapters/grpc/proto --go-grpc_opt=paths=source_relative \
		       internal/adapters/grpc/proto/*.proto; \
		echo "Protocol Buffer code generated successfully."; \
	else \
		echo "Directory internal/adapters/grpc/proto not found. Skipping proto generation."; \
	fi

.PHONY: wire
wire:
	@echo "Running Wire to generate dependency injection code..."
	@# Ensure Wire is installed (e.g., go install github.com/google/wire/cmd/wire@latest)
	@# This command assumes wire can be run from the project root,
	@# or your //go:generate directives are set up correctly.
	@# Alternatively, cd into the directory containing wire.go files (e.g., internal/bootstrap)
	@if [ -f "internal/bootstrap/wire.go" ] || [ -n "$(shell find internal/bootstrap -name 'wire.go')" ]; then \
		(cd internal/bootstrap && go generate .) || wire gen ./... ; \
		echo "Wire code generated successfully."; \
	elif command -v wire >/dev/null 2>&1; then \
		wire gen ./... ; \
		echo "Wire code generated successfully (ran 'wire gen ./...')."; \
	else \
		echo "Wire tool not found or no wire.go files in internal/bootstrap. Skipping wire generation."; \
		echo "Consider 'go install github.com/google/wire/cmd/wire@latest'"; \
	fi

.PHONY: tidy
tidy:
	@echo "Running go mod tidy..."
	go mod tidy

.PHONY: format
format:
	@echo "Formatting Go files..."
	go fmt $(GO_FILES)

# Benchmark targets
.PHONY: benchmark
benchmark:
	@echo "Running all benchmark tests with profiling..."
	@./scripts/run-benchmarks.sh

.PHONY: benchmark-auth
benchmark-auth:
	@echo "Running authentication benchmark tests..."
	@mkdir -p benchmark-results/profiles
	go test -bench=BenchmarkUserTokenValidation -benchtime=10s -count=3 \
		-cpuprofile=benchmark-results/profiles/auth-cpu.prof \
		-memprofile=benchmark-results/profiles/auth-mem.prof \
		./benchmarks/auth_bench_test.go

.PHONY: benchmark-conn
benchmark-conn:
	@echo "Running connection management benchmark tests..."
	@mkdir -p benchmark-results/profiles
	go test -bench=BenchmarkConnection -benchtime=10s -count=3 \
		-cpuprofile=benchmark-results/profiles/conn-cpu.prof \
		-memprofile=benchmark-results/profiles/conn-mem.prof \
		./benchmarks/connection_bench_test.go

.PHONY: benchmark-msg
benchmark-msg:
	@echo "Running message processing benchmark tests..."
	@mkdir -p benchmark-results/profiles
	go test -bench=BenchmarkMessage -benchtime=10s -count=3 \
		-cpuprofile=benchmark-results/profiles/msg-cpu.prof \
		-memprofile=benchmark-results/profiles/msg-mem.prof \
		./benchmarks/message_bench_test.go

.PHONY: benchmark-integration
benchmark-integration:
	@echo "Running integration benchmark tests..."
	@mkdir -p benchmark-results/profiles
	go test -bench="BenchmarkFullUserFlow|BenchmarkMessageFlow|BenchmarkSessionManagementFlow|BenchmarkHighLoadScenario" -benchtime=5s -count=2 \
		-cpuprofile=benchmark-results/profiles/integration-cpu.prof \
		-memprofile=benchmark-results/profiles/integration-mem.prof \
		./benchmarks/

.PHONY: benchmark-compare
benchmark-compare:
	@echo "Comparing benchmark results with baseline..."
	@./scripts/benchmark-compare.sh

.PHONY: benchmark-clean
benchmark-clean:
	@echo "Cleaning benchmark results..."
	@rm -rf benchmark-results/ 