# TODO List

## `cmd/daisi-ws-service/main.go`
- Implement actual readiness checks for the `/ready` endpoint (e.g., NATS, Redis connections).
- Add production hardening to HTTP server (ReadTimeout, WriteTimeout, IdleTimeout).
- Add cleanup for other resources (NATS, Redis, gRPC server) during graceful shutdown.

## `internal/adapters/websocket/handler.go`
- TODO: (From code comment) Later, the `AuthenticatedUserContext` from `CompanyTokenAuthMiddleware` should be retrieved and utilized within `ServeHTTP` and `manageConnection` for more detailed logging, context-aware operations, and passing user details to NATS subscription logic. (Partially addressed, core details are used; further clarification on "more detailed" aspects might be needed).
- TODO: (FR-9B from code comment) Add WebSocket compression options to `websocket.AcceptOptions` based on application configuration.
- TODO: (FR-9B from code comment) Consider adding `InsecureSkipVerify` to `websocket.AcceptOptions` for local development if using self-signed certificates, controlled by application configuration.
- Implement remaining Client Message Processing logic within `manageConnection` for `json.v1` subprotocol. This primarily includes:
    - Defining behavior for other potential client message types or unknown types (e.g., sending `ErrorMessage`). (Partially done, `handleUnknownMessage` exists, ongoing as new types may emerge).

## `internal/adapters/redis/token_cache_adapter.go`
- **Implement Redis Token Cache Adapter**
  - Corresponding to `// TODO: Implement appredis.NewTokenCacheAdapter in internal/adapters/redis/token_cache_adapter.go` in `internal/bootstrap/providers.go`.
  - Create `internal/adapters/redis/token_cache_adapter.go`.
  - Implement the `NewTokenCacheAdapter` function and the necessary methods to satisfy the `domain.TokenCacheStore` interface using Redis.
  - Update `TokenCacheStoreProvider` in `internal/bootstrap/providers.go` to use the implemented adapter.

## Admin Functionality
- **Admin Token Generation & Scoping**: Implement a mechanism for generating admin tokens. Ensure that the process populates `AdminUserContext.SubscribedCompanyID` and `AdminUserContext.SubscribedAgentID` appropriately. This is crucial for correct NATS topic subscriptions in `AdminHandler` for agent events (FR-ADMIN-2).
  - Consider creating a new admin-specific token generation endpoint (e.g., `/admin/generate-token`) or an offline utility script.
  - Define how an admin's scope (e.g., global vs. company-specific) translates to `SubscribedCompanyID` and `SubscribedAgentID` in the token.

## `internal/bootstrap/providers.go`
- TODO: (From code comment line 142) Add `ReadTimeoutSeconds` and `IdleTimeoutSeconds` to `config.AppConfig` and use them in `HTTPGracefulServerProvider`.

- TODO: FR-8C (`websocket/handler.go`): Implement gRPC client connection pooling/reuse for inter-pod communication. **(New specific TODO)**

--- 

# Completed TODO

## Recently Addressed from this Session
- **`cmd/daisi-ws-service/main.go`**: Implemented actual readiness checks for the `/ready` endpoint (NATS, Redis).
- **`cmd/daisi-ws-service/main.go`**: Added production hardening to HTTP server (ReadTimeout, WriteTimeout, IdleTimeout via config).
- **`cmd/daisi-ws-service/main.go`**: Verified cleanup for NATS, Redis, gRPC server during graceful shutdown (handled by Wire & provider cleanups).
- **`internal/adapters/websocket/handler.go`**: Added configurable WebSocket compression options to `websocket.AcceptOptions`.
- **`internal/adapters/websocket/handler.go`**: Added configurable `InsecureSkipVerify` to `websocket.AcceptOptions` for local development.
- **`internal/adapters/websocket/handler.go`**: Implemented NATS subscription logic: initial general `wa.C.A.chats` subscription, then switch to specific `wa.C.A.messages.chatID` on `MessageTypeSelectChat`, including draining previous subscriptions.
- **`internal/adapters/redis/token_cache_adapter.go`**: Implemented Redis Token Cache Adapter (`NewTokenCacheAdapter` and `domain.TokenCacheStore` methods) and updated `TokenCacheStoreProvider`.
- **Admin Functionality**: Implemented Admin Token Generation & Scoping (`/admin/generate-token` endpoint, `AdminUserContext` population for NATS scoping).
- **`internal/bootstrap/providers.go`**: Added `ReadTimeoutSeconds` and `IdleTimeoutSeconds` to `config.AppConfig` and used them in `HTTPGracefulServerProvider` (covered by HTTP server hardening).
- **FR-8C (`websocket/handler.go`)**: Implemented basic gRPC client connection pooling/reuse for inter-pod communication in `specificChatNatsMessageHandler`.

## Previously Completed (Task 7 & related from Task 4)
- Client Message Processing: Unmarshalling incoming messages into `BaseMessage`. (Completed in Task 4 / Task 7)
- Handling `MessageTypeSelectChat`:
    - Parsing `SelectChatMessagePayload`. (Completed in Task 7.3)
    - Implementing dynamic Redis route registration logic with ConnectionManager/RouteRegistry. (Completed in Task 7.1, 7.2, 7.4)

## Tooling & Environment
- **Setup protoc and Go gRPC plugins**: The `protoc` compiler and `protoc-gen-go`, `protoc-gen-go-grpc` plugins are needed to generate Go code from `.proto` files for gRPC communication (Task 8). Install them and ensure they are in the system PATH. - Task 8 completed, but this remains generally good practice for future proto changes.

## Task 8 Follow-ups (gRPC & NATS Handling)
- TODO: FR-8A (`websocket/handler.go`): Refine behavior for `ErrNoOwningPod` from Redis when checking NATS message route ownership. If no owner, should any pod process, or should it be dropped/NACKed to avoid duplicates? Consider implications for message loss vs. duplicate processing. **(Decision: NACKed, Implemented)**
- TODO: FR-8B (`websocket/handler.go`): Implement proper pod address resolution for gRPC client (e.g., from K8s service discovery or config map) instead of assuming `ownerPodID:GRPCPort`. **(Suggestion added, implementation pending user)**
- TODO: (`grpc/server.go`): Enable gRPC reflection for development/debug builds based on configuration. **(Implemented)**
- TODO: (`nats/consumer.go`, `websocket/handler.go`): Make NATS `AckWait` and gRPC client timeout configurable. **(NATS AckWait was already configurable. gRPC client timeout implemented)**

## Task 10 Follow-ups (Metrics & Tracing)
- TODO: (`websocket/handler.go`, `admin_handler.go`): Implement `request_id` extraction from NATS message headers/payload (if present) or generation for NATS-consumed messages. Ensure this `request_id` is added to the context used for subsequent logging and gRPC calls. **(Implemented: NATS messages now have request_id in context for logging and gRPC propagation in user handler; admin handler has it for logging.)**
- TODO: (Task 10.5 Clarification): Clarify the requirement for "JetStream Lag Awareness". Determine if this service needs to actively query NATS and expose a Prometheus metric for consumer lag, or if it's an operational concern for an external NATS exporter and HPA configuration. **(Clarified - Operational Concern, no code changes needed in this service)**