# Builder Stage
ARG GO_VERSION=1.23
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /app

# Set CGO_ENABLED=0 for static builds
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the rest of the application source code
COPY . .

# Build the application
# Output binary to /app/daisi-ws-service
RUN go build -v -o /app/daisi-ws-service ./cmd/daisi-ws-service

# ---

# Final Stage
FROM debian:bookworm-slim

WORKDIR /app

# Create a non-root user and group
RUN groupadd --system appuser && useradd --system --gid appuser appuser

# Copy the compiled binary from the builder stage
COPY --from=builder /app/daisi-ws-service /app/daisi-ws-service

# Copy configuration (assuming it will be in /app/config)
# We might need to adjust this later if config path changes or is mounted differently
COPY config /app/config 
# Ensure the config directory and file have correct permissions if they exist
# RUN if [ -d /app/config ]; then chown -R appuser:appuser /app/config && chmod -R u+rX,g+rX /app/config; fi

# Set permissions for the binary
RUN chown appuser:appuser /app/daisi-ws-service && chmod u+x /app/daisi-ws-service

# Switch to the non-root user
USER appuser

# Expose the default port the application will listen on (adjust if necessary)
# Placeholder, will be defined by HTTP/gRPC server implementation later
# EXPOSE 8080 
# EXPOSE 50051

# Set the entrypoint
ENTRYPOINT ["/app/daisi-ws-service"] 