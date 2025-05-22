# Makefile for managing the Daisi unified Docker Compose setup
# Located in the daisi/ directory, alongside docker-compose.yaml

# Default target executed when no arguments are given to make.
.PHONY: default
default: help

# Variables
COMPOSE_FILE := docker-compose.yaml

# -----------------------------------------------------------------------------
# Core Docker Compose Commands
# -----------------------------------------------------------------------------

.PHONY: up
up: ## Start all services in detached mode
	docker-compose -f $(COMPOSE_FILE) up -d --scale ws-service=2

.PHONY: up-core-infra
up-core-infra: ## Start only PostgreSQL, NATS, and message-event-service in detached mode
	docker-compose -f $(COMPOSE_FILE) up -d postgres nats redis message-event-service

.PHONY: down
down: ## Stop and remove all services
	docker-compose -f $(COMPOSE_FILE) down

.PHONY: stop
stop: ## Stop all services without removing them
	docker-compose -f $(COMPOSE_FILE) stop

.PHONY: start
start: ## Start existing stopped services
	docker-compose -f $(COMPOSE_FILE) start

.PHONY: restart
restart: ## Restart all services
	docker-compose -f $(COMPOSE_FILE) restart

.PHONY: ps
ps: ## List running services
	docker-compose -f $(COMPOSE_FILE) ps

.PHONY: logs
logs: ## View logs from all services (follow mode)
	docker-compose -f $(COMPOSE_FILE) logs -f

.PHONY: logs-service
logs-service: ## View logs for a specific service (e.g., make logs-service s=ws-service)
	@read -p "Enter service name: " s; \
	docker-compose -f $(COMPOSE_FILE) logs -f $$s

# -----------------------------------------------------------------------------
# Build & Configuration
# -----------------------------------------------------------------------------

.PHONY: build
build: ## Build or rebuild services that have a Dockerfile (ws-service, cdc-consumer-service)
	docker-compose -f $(COMPOSE_FILE) build --no-cache ws-service cdc-consumer-service

.PHONY: build-service
build-service: ## Build or rebuild a specific service (e.g., make build-service s=ws-service)
	@read -p "Enter service name to build: " s; \
	docker-compose -f $(COMPOSE_FILE) build --no-cache $$s

.PHONY: config
config: ## Validate and view the compose file configuration
	docker-compose -f $(COMPOSE_FILE) config

.PHONY: lint
lint: config ## Alias for config, validates the docker-compose file

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

.PHONY: clean
clean: down ## Stop and remove containers, networks, and volumes defined in compose
	docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans

.PHONY: prune
prune: ## Remove all stopped containers, unused networks, dangling images, and build cache
	@echo "Removing all stopped containers, unused networks, and dangling images..."
	docker system prune -af
	@echo "Removing build cache..."
	docker builder prune -af

# -----------------------------------------------------------------------------
# Utility
# -----------------------------------------------------------------------------

.PHONY: help
help: ## Display this help screen
	@awk 'BEGIN {FS = ":.*?## "; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?## / { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Notes for user:
# 1. Ensure Docker and Docker Compose are installed and running.
# 2. Run `make build` first if you have made changes to the Dockerfiles of ws-service or cdc-consumer-service.
# 3. The `daisi/docker-compose.yaml` file has notes regarding placeholder values (secrets, API keys)
#    and required configuration files (Prometheus, Grafana provisioning, Sequin DB init script).
#    Please review and complete these before running `make up`.
# 4. To scale services like `ws-service` (planned for 2 replicas):
#    `docker-compose -f docker-compose.yaml up -d --scale ws-service=2` 