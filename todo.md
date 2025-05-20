# TODO List

--- 

# Completed TODO

## Recently Addressed from this Session
- **`cmd/daisi-ws-service/main.go`**: Implemented actual readiness checks for the `/ready` endpoint (NATS, Redis).
- **`cmd/daisi-ws-service/main.go`**: Added production hardening to HTTP server (ReadTimeout, WriteTimeout, IdleTimeout via config).
- **`cmd/daisi-ws-service/main.go`**: Verified cleanup for NATS, Redis, gRPC server during graceful shutdown (handled by Wire & provider cleanups).
- **`internal/adapters/websocket/handler.go`**: Added configurable WebSocket compression options to `websocket.AcceptOptions`.
- **`internal/adapters/websocket/handler.go`**: Added configurable `InsecureSkipVerify` to `websocket.AcceptOptions` for local development.
- **`internal/adapters/websocket/handler.go`**: Implemented NATS subscription logic: initial general `wa.C.A.chats` subscription, then switch to specific `wa.C.A.messages.chatID` on `MessageTypeSelectChat`, including draining previous subscriptions.
- **`internal/adapters/websocket/handler.go`**: the `AuthenticatedUserContext` from `CompanyTokenAuthMiddleware` should be retrieved and utilized within `ServeHTTP` and `manageConnection` for more detailed logging, context-aware operations, and passing user details to NATS subscription logic. (Partially addressed, core details are used; further clarification on "more detailed" aspects might be needed).
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

- **`internal/bootstrap/app.go`**: Add other checks like gRPC server health if applicable in the future
- **`internal/adapters/nats/consumer.go`**: Add more robust connection options from config (e.g., timeouts, reconnectWait, maxReconnect)
- **`internal/adapters/websocket/handler.go`**: Add a basic health check here if possible. For now, assume good or will error out on use.

## New Todos - 2025-05-20

- TODO: (Task 14.3 Follow-up) Conduct thorough testing of the advanced gRPC connection pooling features (idle timeout, health checks, circuit breaker) under various conditions (normal, failure, high load). -- Later in testing phase.
- TODO: (Task 14.4 Follow-up) Conduct thorough testing of WebSocket message buffering and backpressure handling, especially the "drop_oldest" and "block" policies. -- Later in testing phase.
- TODO: (Task 14.4 Follow-up) Refine or implement robust slow client detection logic for WebSocket connections. The current config fields `WebsocketSlowClientLatencyMs` and `WebsocketSlowClientDisconnectThresholdMs` are placeholders. -- SKIP, no need
- TODO: (Task 14.4 Follow-up) Review and verify NATS ACK/NACK interaction with the WebSocket buffering. Specifically:
    - If a message is dropped from the buffer due to `drop_oldest` policy, the NATS message should be ACKed.
    - If `WriteJSON` uses the `block` policy and the parent context (e.g., NATS message processing context) times out or is cancelled while `WriteJSON` is blocked trying to send to the buffer, determine if the NATS message should be NACKed or allowed to time out for redelivery.
    - Ensure that messages successfully written from the buffer to the WebSocket by the writer goroutine result in the original NATS message being ACKed (this is handled by the caller of `WriteJSON` currently, but needs to be robust if `WriteJSON` itself can block for extended periods).
