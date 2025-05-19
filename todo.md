# TODO List

## `cmd/daisi-ws-service/main.go`
- Implement actual readiness checks for the `/ready` endpoint (e.g., NATS, Redis connections).
- Add production hardening to HTTP server (ReadTimeout, WriteTimeout, IdleTimeout).
- Add cleanup for other resources (NATS, Redis, gRPC server) during graceful shutdown.

## General
- Build and run Docker image to test `Dockerfile` and application execution (deferred from Subtask 1.2).
- Test `/health` and `/ready` endpoints and log output (deferred from Subtask 1.4).

## `internal/adapters/websocket/handler.go`
- TODO: (From code comment) Later, the `AuthenticatedUserContext` from `CompanyTokenAuthMiddleware` should be retrieved and utilized within `ServeHTTP` and `manageConnection` for more detailed logging, context-aware operations, and passing user details to NATS subscription logic.
- TODO: (FR-9B from code comment) Add WebSocket compression options to `websocket.AcceptOptions` based on application configuration.
- TODO: (FR-9B from code comment) Consider adding `InsecureSkipVerify` to `websocket.AcceptOptions` for local development if using self-signed certificates, controlled by application configuration.
- Implement remaining Client Message Processing logic within `manageConnection` for `json.v1` subprotocol. This primarily includes:
    - For `MessageTypeSelectChat`: **Still TODO**: Updating NATS subscriptions to switch from the general `wa.<C>.<A>.chats` stream to the specific `wa.<C>.<A>.messages.<chatID>` stream, and managing unsubscription from previous specific chat message streams. This is crucial for FR-7 and will likely require refactoring NATS subscription management in `manageConnection` and potentially adding a new subscription method to the NATS adapter for specific message threads.
    - Defining behavior for other potential client message types or unknown types (e.g., sending `ErrorMessage`). (Partially done, `handleUnknownMessage` exists)

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

--- 

# Completed TODO
## Recently Completed (Task 7 & related from Task 4)
- Client Message Processing: Unmarshalling incoming messages into `BaseMessage`. (Completed in Task 4 / Task 7)
- Handling `MessageTypeSelectChat`:
    - Parsing `SelectChatMessagePayload`. (Completed in Task 7.3)
    - Implementing dynamic Redis route registration logic with ConnectionManager/RouteRegistry. (Completed in Task 7.1, 7.2, 7.4)
