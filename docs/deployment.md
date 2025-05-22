# Deployment Guide for daisi-ws-service

This guide provides instructions for deploying `daisi-ws-service` to a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (1.23+)
- kubectl configured to communicate with your cluster
- Helm 3.x
- Access to container registry with daisi images

## Architecture Overview

The `daisi-ws-service` is part of a larger ecosystem that includes:

- NATS JetStream for event streaming
- Redis for session management and routing
- PostgreSQL for persistent storage
- Sequin for change data capture (CDC)
- Observability stack (Prometheus, Grafana, Loki)

### System Components

The Daisi platform consists of several interconnected services:

1. **daisi-ws-service**: WebSocket service that handles client connections and message routing
2. **daisi-message-event-service**: Processes and stores message events
3. **daisi-cdc-consumer-service**: Consumes change data capture events from Sequin
4. **Sequin**: Captures database changes from PostgreSQL and publishes them to NATS
5. **Infrastructure services**: PostgreSQL, Redis, NATS JetStream

### Local Development Environment

For local development, a Docker Compose setup is provided that deploys all required components. A Makefile in the `deploy` directory provides convenient commands for managing the local environment:

```bash
# Start all services
make -f deploy/Makefile up

# Start only core infrastructure
make -f deploy/Makefile up-core-infra

# View logs from all services
make -f deploy/Makefile logs

# View logs for a specific service
make -f deploy/Makefile logs-service

# Stop and remove all services
make -f deploy/Makefile down

# Build specific service images
make -f deploy/Makefile build-service
```

## Deployment Steps

### 1. Create Namespace

```bash
kubectl create namespace daisi
```

### 2. Deploy Infrastructure Services

First, deploy the core infrastructure services that `daisi-ws-service` depends on:

#### PostgreSQL

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-init
  namespace: daisi
data:
  init-db.sql: |
    CREATE DATABASE sequin_db;
```

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: daisi
spec:
  serviceName: "postgres"
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:17-bookworm
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_USER
          value: "postgres"
        - name: POSTGRES_PASSWORD
          value: "postgres"  # Use Kubernetes secrets in production
        - name: POSTGRES_DB
          value: "message_service_db"
        args: ["postgres", "-c", "wal_level=logical"]
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
        - name: postgres-init
          mountPath: /docker-entrypoint-initdb.d
  volumeClaimTemplates:
  - metadata:
      name: postgres-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: daisi
spec:
  ports:
  - port: 5432
    targetPort: 5432
  selector:
    app: postgres
```

#### NATS JetStream

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: nats
  namespace: daisi
spec:
  serviceName: "nats"
  replicas: 1
  selector:
    matchLabels:
      app: nats
  template:
    metadata:
      labels:
        app: nats
    spec:
      containers:
      - name: nats
        image: nats:2.11-alpine
        args: ["--name", "unified-nats-server", "--http_port", "8222", "--jetstream", "--store_dir", "/data"]
        ports:
        - containerPort: 4222
        - containerPort: 6222
        - containerPort: 8222
        volumeMounts:
        - name: nats-data
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: nats-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 5Gi
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nats
  namespace: daisi
spec:
  ports:
  - name: client
    port: 4222
    targetPort: 4222
  - name: cluster
    port: 6222
    targetPort: 6222
  - name: monitor
    port: 8222
    targetPort: 8222
  selector:
    app: nats
```

#### Redis

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
  namespace: daisi
spec:
  serviceName: "redis"
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-data
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: redis-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 2Gi
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: daisi
spec:
  ports:
  - port: 6379
    targetPort: 6379
  selector:
    app: redis
```

### 3. Configure Sequin

Sequin is responsible for Change Data Capture (CDC) from PostgreSQL to NATS. For each company table that needs to be tracked, we configure sinks in Sequin.

Create a ConfigMap for the Sequin configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sequin-config
  namespace: daisi
data:
  daisi-sequin.yml: |
    account:
      name: "Daisi"
    
    users:
      - account: "Daisi"
        email: "admin@sequinstream.com"
        password: "password"
    
    databases:
      - name: message_service_db
        port: 5432
        ssl: false
        ipv6: false
        hostname: postgres
        password: postgres
        username: postgres
        pool_size: 10
        database: message_service_db
        use_local_tunnel: false
        slot_name: daisi_slot
        publication_name: daisi_pub
    
    sinks:
      - name: global00_messages_sink
        status: active
        table: daisi_CompanyGLOBAL00.messages
        filters: []
        transform: none
        destination:
          port: 4222
          type: nats
          host: nats
          tls: false
        actions:
          - insert
          - update
          - delete
        batch_size: 1
        database: message_service_db
        timestamp_format: iso8601
        group_column_names:
          - message_id
          - message_date
      - name: global00_chats_sink
        status: active
        table: daisi_CompanyGLOBAL00.chats
        filters: []
        transform: none
        destination:
          port: 4222
          type: nats
          host: nats
          tls: false
        actions:
          - insert
          - update
          - delete
        batch_size: 1
        database: message_service_db
        timestamp_format: iso8601
        group_column_names:
          - chat_id
      - name: global00_agents_sink
        status: active
        table: daisi_CompanyGLOBAL00.agents
        filters: []
        transform: none
        destination:
          port: 4222
          type: nats
          host: nats
          tls: false
        actions:
          - insert
          - update
          - delete
        batch_size: 1
        database: message_service_db
        timestamp_format: iso8601
        group_column_names:
          - agent_id
```

Deploy Sequin:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sequin
  namespace: daisi
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sequin
  template:
    metadata:
      labels:
        app: sequin
    spec:
      containers:
      - name: sequin
        image: sequin/sequin:latest
        ports:
        - containerPort: 7376
        env:
        - name: PG_HOSTNAME
          value: postgres
        - name: PG_DATABASE
          value: sequin_db
        - name: PG_PORT
          value: "5432"
        - name: PG_USERNAME
          value: "postgres"
        - name: PG_PASSWORD
          value: "postgres"  # Use Kubernetes secrets in production
        - name: PG_POOL_SIZE
          value: "20"
        - name: SECRET_KEY_BASE
          value: "wDPLYus0pvD6qJhKJICO4dauYPXfO/Yl782Zjtpew5qRBDp7CZvbWtQmY0eB13If"  # Use Kubernetes secrets in production
        - name: VAULT_KEY
          value: "2Sig69bIpuSm2kv0VQfDekET2qy8qUZGI8v3/h3ASiY="  # Use Kubernetes secrets in production
        - name: REDIS_URL
          value: "redis://redis:6379"
        - name: CONFIG_FILE_PATH
          value: "/config/daisi-sequin.yml"
        volumeMounts:
        - name: sequin-config
          mountPath: /config
      volumes:
      - name: sequin-config
        configMap:
          name: sequin-config
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sequin
  namespace: daisi
spec:
  ports:
  - port: 7376
    targetPort: 7376
  selector:
    app: sequin
```

### 4. Deploy Message Event Service

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: message-event-service
  namespace: daisi
spec:
  replicas: 1
  selector:
    matchLabels:
      app: message-event-service
  template:
    metadata:
      labels:
        app: message-event-service
    spec:
      containers:
      - name: message-event-service
        image: daisi/daisi-message-event-service:latest
        ports:
        - containerPort: 8081
        env:
        - name: POSTGRES_DSN
          value: "postgres://postgres:postgres@postgres:5432/message_service_db"
        - name: NATS_URL
          value: "nats://nats:4222"
        - name: COMPANY_ID
          value: "CompanyGLOBAL00"
        - name: LOG_LEVEL
          value: "info"
        - name: MES_SERVER_PORT
          value: "8081"
        - name: MES_METRICS_ENABLED
          value: "true"
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: message-event-service
  namespace: daisi
spec:
  ports:
  - port: 8081
    targetPort: 8081
  selector:
    app: message-event-service
```

### 5. Deploy CDC Consumer Service

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cdc-consumer-service
  namespace: daisi
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cdc-consumer-service
  template:
    metadata:
      labels:
        app: cdc-consumer-service
    spec:
      containers:
      - name: cdc-consumer-service
        image: daisi/daisi-cdc-consumer-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: DAISI_CDC_NATS_URL
          value: "nats://nats:4222"
        - name: DAISI_CDC_REDIS_ADDR
          value: "redis://redis:6379"
        - name: DAISI_CDC_LOG_LEVEL
          value: "debug"
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: cdc-consumer-service
  namespace: daisi
spec:
  ports:
  - port: 8082
    targetPort: 8080
  selector:
    app: cdc-consumer-service
```

### 6. Deploy WebSocket Service

Create ConfigMap for the WebSocket service configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ws-service-config
  namespace: daisi
data:
  config.yaml: |
    server:
      http_port: 8080
      grpc_port: 50051
      pod_id: "${POD_IP}"
      enable_reflection: true
    
    nats:
      url: "nats://nats:4222"
      stream_name: "wa_stream"
      consumer_name: "ws_fanout"
      connect_timeout_seconds: 30
      reconnect_wait_seconds: 5
      max_reconnects: 10
      ping_interval_seconds: 30
      max_pings_out: 2
      retry_on_failed_connect: true
    
    redis:
      address: "redis:6379"
      password: ""
      db: 0
    
    log:
      level: "debug"
    
    auth:
      token_cache_ttl_seconds: 30
      admin_token_cache_ttl_seconds: 30
    
    app:
      service_name: "daisi-ws-service"
      version: "1.0.0"
      ping_interval_seconds: 20
      shutdown_timeout_seconds: 30
      pong_wait_seconds: 45
      write_timeout_seconds: 10
      max_missed_pongs: 2
      session_ttl_seconds: 30
      route_ttl_seconds: 30
      ttl_refresh_interval_seconds: 10
      nats_max_ack_pending: 5000
      session_lock_retry_delay_ms: 100
      nats_ack_wait_seconds: 30
      grpc_client_forward_timeout_seconds: 5
      read_timeout_seconds: 5
      idle_timeout_seconds: 60
      websocket_message_buffer_size: 256
      websocket_backpressure_drop_policy: "drop_oldest"
      websocket_slow_client_latency_ms: 1000
      websocket_slow_client_disconnect_threshold_ms: 5000
    
    adaptive_ttl:
      session_lock:
        enabled: true
        min_ttl_seconds: 15
        max_ttl_seconds: 60
        activity_threshold_seconds: 300
        active_ttl_seconds: 30
        inactive_ttl_seconds: 15
      message_route:
        enabled: true
        min_ttl_seconds: 15
        max_ttl_seconds: 60
        activity_threshold_seconds: 300
        active_ttl_seconds: 30
        inactive_ttl_seconds: 15
      chat_route:
        enabled: true
        min_ttl_seconds: 15
        max_ttl_seconds: 60
        activity_threshold_seconds: 300
        active_ttl_seconds: 30
        inactive_ttl_seconds: 15
```

Deploy WebSocket Service:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ws-service
  namespace: daisi
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ws-service
  template:
    metadata:
      labels:
        app: ws-service
    spec:
      containers:
      - name: ws-service
        image: daisi/daisi-ws-service:latest
        ports:
        - name: http
          containerPort: 8080
        - name: grpc
          containerPort: 50051
        env:
        - name: DAISI_WS_SERVER_HTTP_PORT
          value: "8080"
        - name: DAISI_WS_SERVER_GRPC_PORT
          value: "50051"
        - name: DAISI_WS_SERVER_POD_ID
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: DAISI_WS_SERVER_ENABLE_REFLECTION
          value: "true"
        - name: DAISI_WS_NATS_URL
          value: "nats://nats:4222"
        - name: DAISI_WS_NATS_STREAM_NAME
          value: "wa_stream"
        - name: DAISI_WS_NATS_CONSUMER_NAME
          value: "ws_fanout"
        - name: DAISI_WS_REDIS_ADDRESS
          value: "redis:6379"
        - name: DAISI_WS_LOG_LEVEL
          value: "debug"
        - name: DAISI_WS_APP_SERVICE_NAME
          value: "daisi-ws-service"
        - name: DAISI_WS_APP_VERSION
          value: "1.0.0"
        - name: DAISI_WS_AUTH_SECRET_TOKEN
          value: "n7f2GTfsHqNNNaDWaPeV9I4teCGqnmtv"  # Use Kubernetes secrets in production
        - name: DAISI_WS_AUTH_TOKEN_AES_KEY
          value: "270cec3a9081be630f5350bc42b244156615e55a2153e2652dc4f460673350c6"  # Use Kubernetes secrets in production
        - name: DAISI_WS_AUTH_TOKEN_GENERATION_ADMIN_KEY
          value: "SDzNfhTMqhnEGSp8mze4YpXt5RYXTidX"  # Use Kubernetes secrets in production
        - name: DAISI_WS_AUTH_ADMIN_TOKEN_AES_KEY
          value: "97c2f43def2596ff2d635e924f6de7918b2eb1b79b761974c2493afb597c9e1b"  # Use Kubernetes secrets in production
        volumeMounts:
        - name: ws-service-config
          mountPath: /app/config
      volumes:
      - name: ws-service-config
        configMap:
          name: ws-service-config
```

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ws-service
  namespace: daisi
spec:
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: grpc
    port: 50051
    targetPort: 50051
  selector:
    app: ws-service
```

### 7. Deploy Observability Stack

The observability stack consists of Prometheus for metrics collection, Grafana for visualization, and Loki with Promtail for log aggregation.

#### 7.1 Deploy Prometheus

Create a ConfigMap for Prometheus configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: daisi
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
    
    scrape_configs:
      - job_name: 'prometheus'
        static_configs:
          - targets: ['localhost:9090']
      
      - job_name: 'message-event-service'
        static_configs:
          - targets: ['message-event-service:8081']
      
      - job_name: 'ws-service'
        kubernetes_sd_configs:
          - role: pod
            namespaces:
              names: ['daisi']
        relabel_configs:
          - source_labels: [__meta_kubernetes_pod_label_app]
            regex: ws-service
            action: keep
          - source_labels: [__meta_kubernetes_pod_container_port_number]
            regex: 8080
            action: keep
      
      - job_name: 'cdc-consumer-service'
        static_configs:
          - targets: ['cdc-consumer-service:8080']
      
      - job_name: 'nats-exporter'
        static_configs:
          - targets: ['nats-exporter:7777']
      
      - job_name: 'sequin'
        static_configs:
          - targets: ['sequin:8376']
```

Deploy Prometheus:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: daisi
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus:latest
        ports:
        - containerPort: 9090
        volumeMounts:
        - name: prometheus-config
          mountPath: /etc/prometheus
        - name: prometheus-data
          mountPath: /prometheus
        args:
        - "--config.file=/etc/prometheus/prometheus.yml"
        - "--storage.tsdb.path=/prometheus"
      volumes:
      - name: prometheus-config
        configMap:
          name: prometheus-config
      - name: prometheus-data
        persistentVolumeClaim:
          claimName: prometheus-data
```

Create a PVC for Prometheus data:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: prometheus-data
  namespace: daisi
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

Create a Service for Prometheus:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: prometheus
  namespace: daisi
spec:
  ports:
  - port: 9090
    targetPort: 9090
  selector:
    app: prometheus
```

#### 7.2 Deploy Loki and Promtail

Create ConfigMap for Loki:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: loki-config
  namespace: daisi
data:
  loki-config.yml: |
    auth_enabled: false
    
    server:
      http_listen_port: 3100
      grpc_listen_port: 9096
    
    common:
      instance_addr: 127.0.0.1
      path_prefix: /loki 
      storage:
        filesystem:
          chunks_directory: /loki/chunks
          rules_directory: /loki/rules
      replication_factor: 1
      ring:
        kvstore:
          store: inmemory
    
    schema_config:
      configs:
        - from: 2020-10-24
          store: tsdb
          object_store: filesystem
          schema: v13
          index:
            prefix: index_
            period: 24h
```

Deploy Loki:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: loki
  namespace: daisi
spec:
  replicas: 1
  selector:
    matchLabels:
      app: loki
  template:
    metadata:
      labels:
        app: loki
    spec:
      containers:
      - name: loki
        image: grafana/loki:3.0.0
        ports:
        - containerPort: 3100
        volumeMounts:
        - name: loki-config
          mountPath: /etc/loki
        - name: loki-data
          mountPath: /loki
        args:
        - "-config.file=/etc/loki/loki-config.yml"
      volumes:
      - name: loki-config
        configMap:
          name: loki-config
      - name: loki-data
        persistentVolumeClaim:
          claimName: loki-data
```

Create ConfigMap for Promtail:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: promtail-config
  namespace: daisi
data:
  promtail-config.yml: |
    server:
      http_listen_port: 9080
      grpc_listen_port: 0
    
    positions:
      filename: /tmp/positions.yaml
    
    clients:
      - url: http://loki:3100/loki/api/v1/push
    
    scrape_configs:
      - job_name: kubernetes-pods
        kubernetes_sd_configs:
          - role: pod
            namespaces:
              names: ['daisi']
        relabel_configs:
          - source_labels: [__meta_kubernetes_pod_label_app]
            action: keep
            regex: .+
          - source_labels: [__meta_kubernetes_pod_label_app]
            target_label: app
          - source_labels: [__meta_kubernetes_pod_name]
            target_label: pod
          - source_labels: [__meta_kubernetes_pod_container_name]
            target_label: container
```

Deploy Promtail as a DaemonSet:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: promtail
  namespace: daisi
spec:
  selector:
    matchLabels:
      app: promtail
  template:
    metadata:
      labels:
        app: promtail
    spec:
      containers:
      - name: promtail
        image: grafana/promtail:2.9.2
        args:
        - -config.file=/etc/promtail/promtail-config.yml
        volumeMounts:
        - name: promtail-config
          mountPath: /etc/promtail
        - name: docker-logs
          mountPath: /var/lib/docker/containers
          readOnly: true
        - name: pods-logs
          mountPath: /var/log/pods
          readOnly: true
      volumes:
      - name: promtail-config
        configMap:
          name: promtail-config
      - name: docker-logs
        hostPath:
          path: /var/lib/docker/containers
      - name: pods-logs
        hostPath:
          path: /var/log/pods
```

#### 7.3 Deploy Grafana with Dashboards

Create ConfigMap for Grafana datasources:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasources
  namespace: daisi
data:
  datasource.yml: |
    apiVersion: 1
    
    datasources:
      - name: Prometheus
        type: prometheus
        access: proxy
        url: http://prometheus:9090
        isDefault: true
        editable: false

  loki-datasource.yml: |
    apiVersion: 1
    
    datasources:
      - name: Loki
        type: loki
        access: proxy
        url: http://loki:3100
        jsonData:
          maxLines: 1000
          derivedFields:
            - datasourceName: Loki
              matcherRegex: "traceID=(\\w+)"
              name: TraceID
              url: "${__value.raw}"
        isDefault: false
```

Create ConfigMap for dashboard provisioning:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboard-provisioning
  namespace: daisi
data:
  dashboards.yml: |
    apiVersion: 1
    
    providers:
      - name: 'default'
        orgId: 1
        folder: '' 
        type: file
        disableDeletion: false
        editable: true
        updateIntervalSeconds: 30
        allowUiUpdates: true
        options:
          path: /var/lib/grafana/dashboards
```

Create ConfigMaps for each dashboard:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-ws-service-dashboard
  namespace: daisi
data:
  ws_service_dashboard.json: |
    {
      "uid": "ws-service-overview",
      "title": "WebSocket Service Overview",
      "tags": ["websocket", "dws"],
      "timezone": "browser",
      "schemaVersion": 16,
      "version": 1,
      "refresh": "10s",
      "panels": [
        {
          "title": "Active WebSocket Connections",
          "type": "stat",
          "datasource": "Prometheus",
          "targets": [
            {
              "expr": "dws_active_connections",
              "legendFormat": "Active"
            }
          ],
          "gridPos": { "h": 4, "w": 12, "x": 0, "y": 0 },
          "options": {
            "reduceOptions": { "calcs": ["lastNotNull"], "fields": "", "values": false },
            "orientation": "horizontal", "textMode": "auto", "colorMode": "value",
            "graphMode": "area", "justifyMode": "auto"
          }
        }
        // Additional panels would continue here...
      ]
    }
```

Create additional ConfigMaps for other dashboards (CDC Consumer, NATS, Sequin, etc).

Deploy Grafana:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: daisi
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
      - name: grafana
        image: grafana/grafana:latest
        ports:
        - containerPort: 3000
        env:
        - name: GF_SECURITY_ADMIN_PASSWORD
          value: "admin"  # Use Kubernetes secrets in production
        - name: GF_PROVISIONING_PATH
          value: "/etc/grafana/provisioning"
        volumeMounts:
        - name: grafana-datasources
          mountPath: /etc/grafana/provisioning/datasources
        - name: grafana-dashboard-provisioning
          mountPath: /etc/grafana/provisioning/dashboards
        - name: grafana-ws-service-dashboard
          mountPath: /var/lib/grafana/dashboards/ws_service_dashboard.json
          subPath: ws_service_dashboard.json
        - name: grafana-data
          mountPath: /var/lib/grafana
      volumes:
      - name: grafana-datasources
        configMap:
          name: grafana-datasources
      - name: grafana-dashboard-provisioning
        configMap:
          name: grafana-dashboard-provisioning
      - name: grafana-ws-service-dashboard
        configMap:
          name: grafana-ws-service-dashboard
      - name: grafana-data
        persistentVolumeClaim:
          claimName: grafana-data
```

Create a service for Grafana:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: daisi
spec:
  ports:
  - port: 3000
    targetPort: 3000
  selector:
    app: grafana
```

#### 7.4 Available Dashboards

The following dashboards are available for monitoring the system:

1. **WebSocket Service Dashboard** - Tracks active connections, connection durations, and gRPC pool metrics
2. **CDC Consumer Dashboard** - Shows event processing rates, latencies, and deduplication statistics
3. **NATS Dashboard** - Monitors connections, message throughput, and JetStream metrics  
4. **Sequin Dashboard** - Tracks CDC capture latency, delivery status, and database operations
5. **Message Events Dashboard** - Shows message processing statistics, database operations, and error rates

### 8. Create Ingress for WebSocket Service

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ws-service-ingress
  namespace: daisi
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "30"
    nginx.ingress.kubernetes.io/proxy-http-version: "1.1"
    nginx.ingress.kubernetes.io/proxy-buffers-number: "4"
    nginx.ingress.kubernetes.io/proxy-buffer-size: "8k"
    nginx.ingress.kubernetes.io/websocket-services: "ws-service"
spec:
  rules:
  - host: ws.daisi.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: ws-service
            port:
              number: 8080
```

## Adding a New Company

When adding a new company to the system, follow these steps:

1. Update the Sequin configuration to include the new company:

   ```bash
   kubectl edit configmap sequin-config -n daisi
   ```

   Add a new sink configuration (make sure to add entries for messages, chats, and agents tables):

   ```yaml
   sinks:
     # Existing sinks
     - name: new_company_messages_sink
       status: active
       table: daisi_CompanyNEW01.messages
       filters: []
       transform: none
       destination:
         port: 4222
         type: nats
         host: nats
         tls: false
       actions:
         - insert
         - update
         - delete
       batch_size: 1
       database: message_service_db
       timestamp_format: iso8601
       group_column_names:
         - message_id
         - message_date
     
     - name: new_company_chats_sink
       status: active
       table: daisi_CompanyNEW01.chats
       filters: []
       transform: none
       destination:
         port: 4222
         type: nats
         host: nats
         tls: false
       actions:
         - insert
         - update
         - delete
       batch_size: 1
       database: message_service_db
       timestamp_format: iso8601
       group_column_names:
         - chat_id
     
     - name: new_company_agents_sink
       status: active
       table: daisi_CompanyNEW01.agents
       filters: []
       transform: none
       destination:
         port: 4222
         type: nats
         host: nats
         tls: false
       actions:
         - insert
         - update
         - delete
       batch_size: 1
       database: message_service_db
       timestamp_format: iso8601
       group_column_names:
         - agent_id
   ```

2. Run the setup SQL script for the new company. This script will:
   - Create the publication if it doesn't exist
   - Create the replication slot if it doesn't exist
   - Set REPLICA IDENTITY FULL for all required tables

   ```bash
   kubectl exec -it postgres-0 -n daisi -- psql -U postgres -d message_service_db -c "
   CREATE PUBLICATION IF NOT EXISTS daisi_pub FOR ALL TABLES WITH (publish_via_partition_root = true);
   
   DO \$\$
   BEGIN
       IF NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_replication_slots
           WHERE slot_name = 'daisi_slot'
       ) THEN
           PERFORM pg_create_logical_replication_slot('daisi_slot', 'pgoutput');
       END IF;
   END;
   \$\$;
   
   DO \$\$
       DECLARE
           v_schema_name TEXT := 'daisi_CompanyNEW01'; -- New company schema name
           v_table_name TEXT := 'messages';
           t regclass;
       BEGIN
           EXECUTE format('ALTER TABLE %I.chats REPLICA IDENTITY FULL', v_schema_name);
           EXECUTE format('ALTER TABLE %I.agents REPLICA IDENTITY FULL', v_schema_name);
           -- parent
           EXECUTE format('ALTER TABLE %I.%I REPLICA IDENTITY FULL', v_schema_name, v_table_name);
   
           FOR t IN
               SELECT inhrelid::regclass
               FROM pg_catalog.pg_inherits
               WHERE inhparent = (quote_ident(v_schema_name) || '.' || quote_ident(v_table_name))::regclass
               LOOP
                   EXECUTE format('ALTER TABLE %s REPLICA IDENTITY FULL;', t);
               END LOOP;
       END;
   \$\$;
   "
   ```

3. Restart Sequin to apply the new configuration:

   ```bash
   kubectl rollout restart deployment sequin -n daisi
   ```

4. Verify the setup is working correctly:

   - Check Sequin logs to confirm the new sinks are created:
     ```bash
     kubectl logs deployment/sequin -n daisi
     ```

   - Verify data is flowing through the system by checking Prometheus metrics:
     ```bash
     # Port-forward to Prometheus
     kubectl port-forward svc/prometheus 9090:9090 -n daisi
     
     # Query metrics related to the new company
     # In Prometheus UI: sequin_messages_ingested_count{table=~"daisi_CompanyNEW01.*"}
     ```

## Configuration Options

The `daisi-ws-service` can be configured via a configuration file (default: `config.yaml`) and environment variables. Environment variables take precedence over configuration file values.

### Environment Variables Mapping

All configuration options can be overridden using environment variables with the `DAISI_WS_` prefix, followed by uppercase section and field names with underscores.

For example:
- `server.http_port` becomes `DAISI_WS_SERVER_HTTP_PORT`
- `nats.url` becomes `DAISI_WS_NATS_URL`

### Server Configuration

| Config File Key | Environment Variable | Description | Default Value |
|-----------------|---------------------|-------------|---------------|
| `server.http_port` | `DAISI_WS_SERVER_HTTP_PORT` | HTTP port for WebSocket connections | `8080` |
| `server.grpc_port` | `DAISI_WS_SERVER_GRPC_PORT` | gRPC port for inter-pod communication | `50051` |
| `server.pod_id` | `DAISI_WS_SERVER_POD_ID` | Pod identifier for session management | Pod IP |
| `server.enable_reflection` | `DAISI_WS_SERVER_ENABLE_REFLECTION` | Enable gRPC reflection | `true` |

### NATS Configuration

| Config File Key | Environment Variable | Description | Default Value |
|-----------------|---------------------|-------------|---------------|
| `nats.url` | `DAISI_WS_NATS_URL` | NATS JetStream URL | `nats://nats:4222` |
| `nats.stream_name` | `DAISI_WS_NATS_STREAM_NAME` | NATS stream name | `wa_stream` |
| `nats.consumer_name` | `DAISI_WS_NATS_CONSUMER_NAME` | NATS consumer name | `ws_fanout` |
| `nats.connect_timeout_seconds` | `DAISI_WS_NATS_CONNECT_TIMEOUT_SECONDS` | NATS connection timeout | `30` |
| `nats.reconnect_wait_seconds` | `DAISI_WS_NATS_RECONNECT_WAIT_SECONDS` | NATS reconnect wait time | `5` |
| `nats.max_reconnects` | `DAISI_WS_NATS_MAX_RECONNECTS` | NATS max reconnects | `10` |
| `nats.ping_interval_seconds` | `DAISI_WS_NATS_PING_INTERVAL_SECONDS` | NATS ping interval | `30` |
| `nats.max_pings_out` | `DAISI_WS_NATS_MAX_PINGS_OUT` | NATS max pings out | `2` |
| `nats.retry_on_failed_connect` | `DAISI_WS_NATS_RETRY_ON_FAILED_CONNECT` | NATS retry on failed connect | `true` |

### Redis Configuration

| Config File Key | Environment Variable | Description | Default Value |
|-----------------|---------------------|-------------|---------------|
| `redis.address` | `DAISI_WS_REDIS_ADDRESS` | Redis address | `redis:6379` |
| `redis.password` | `DAISI_WS_REDIS_PASSWORD` | Redis password | `` |
| `redis.db` | `DAISI_WS_REDIS_DB` | Redis database | `0` |

### Log Configuration

| Config File Key | Environment Variable | Description | Default Value |
|-----------------|---------------------|-------------|---------------|
| `log.level` | `DAISI_WS_LOG_LEVEL` | Log level | `info` |

### Auth Configuration

| Config File Key | Environment Variable | Description | Default Value |
|-----------------|---------------------|-------------|---------------|
| `auth.secret_token` | `DAISI_WS_AUTH_SECRET_TOKEN` | API key secret | *required* |
| `auth.token_aes_key` | `DAISI_WS_AUTH_TOKEN_AES_KEY` | AES key for token encryption | *required* |
| `auth.token_generation_admin_key` | `DAISI_WS_AUTH_TOKEN_GENERATION_ADMIN_KEY` | Admin key for token generation | *required* |
| `auth.token_cache_ttl_seconds` | `DAISI_WS_AUTH_TOKEN_CACHE_TTL_SECONDS` | Token cache TTL | `30` |
| `auth.admin_token_aes_key` | `DAISI_WS_AUTH_ADMIN_TOKEN_AES_KEY` | AES key for admin token encryption | *required* |
| `auth.admin_token_cache_ttl_seconds` | `DAISI_WS_AUTH_ADMIN_TOKEN_CACHE_TTL_SECONDS` | Admin token cache TTL | `30` |

### App Configuration

| Config File Key | Environment Variable | Description | Default Value |
|-----------------|---------------------|-------------|---------------|
| `app.service_name` | `DAISI_WS_APP_SERVICE_NAME` | Service name | `daisi-ws-service` |
| `app.version` | `DAISI_WS_APP_VERSION` | Service version | `1.0.0` |
| `app.ping_interval_seconds` | `DAISI_WS_APP_PING_INTERVAL_SECONDS` | WebSocket ping interval | `20` |
| `app.shutdown_timeout_seconds` | `DAISI_WS_APP_SHUTDOWN_TIMEOUT_SECONDS` | Graceful shutdown timeout | `30` |
| `app.pong_wait_seconds` | `DAISI_WS_APP_PONG_WAIT_SECONDS` | WebSocket pong wait timeout | `45` |
| `app.write_timeout_seconds` | `DAISI_WS_APP_WRITE_TIMEOUT_SECONDS` | WebSocket write timeout | `10` |
| `app.max_missed_pongs` | `DAISI_WS_APP_MAX_MISSED_PONGS` | Max missed pongs before disconnect | `2` |
| `app.session_ttl_seconds` | `DAISI_WS_APP_SESSION_TTL_SECONDS` | Session TTL | `30` |
| `app.route_ttl_seconds` | `DAISI_WS_APP_ROUTE_TTL_SECONDS` | Route TTL | `30` |
| `app.ttl_refresh_interval_seconds` | `DAISI_WS_APP_TTL_REFRESH_INTERVAL_SECONDS` | TTL refresh interval | `10` |
| `app.nats_max_ack_pending` | `DAISI_WS_APP_NATS_MAX_ACK_PENDING` | NATS max ACK pending | `5000` |
| `app.session_lock_retry_delay_ms` | `DAISI_WS_APP_SESSION_LOCK_RETRY_DELAY_MS` | Session lock retry delay | `100` |
| `app.nats_ack_wait_seconds` | `DAISI_WS_APP_NATS_ACK_WAIT_SECONDS` | NATS ACK wait time | `30` |
| `app.grpc_client_forward_timeout_seconds` | `DAISI_WS_APP_GRPC_CLIENT_FORWARD_TIMEOUT_SECONDS` | gRPC client timeout | `5` |
| `app.websocket_message_buffer_size` | `DAISI_WS_APP_WEBSOCKET_MESSAGE_BUFFER_SIZE` | WebSocket message buffer size | `256` |
| `app.websocket_backpressure_drop_policy` | `DAISI_WS_APP_WEBSOCKET_BACKPRESSURE_DROP_POLICY` | WebSocket backpressure policy | `drop_oldest` |

### Adaptive TTL Configuration

| Config File Key | Environment Variable | Description | Default Value |
|-----------------|---------------------|-------------|---------------|
| `adaptive_ttl.session_lock.enabled` | `DAISI_WS_ADAPTIVE_TTL_SESSION_LOCK_ENABLED` | Enable adaptive session TTL | `true` |
| `adaptive_ttl.session_lock.min_ttl_seconds` | `DAISI_WS_ADAPTIVE_TTL_SESSION_LOCK_MIN_TTL_SECONDS` | Min session TTL | `15` |
| `adaptive_ttl.session_lock.max_ttl_seconds` | `DAISI_WS_ADAPTIVE_TTL_SESSION_LOCK_MAX_TTL_SECONDS` | Max session TTL | `60` |
| `adaptive_ttl.session_lock.activity_threshold_seconds` | `DAISI_WS_ADAPTIVE_TTL_SESSION_LOCK_ACTIVITY_THRESHOLD_SECONDS` | Activity threshold | `300` |
| `adaptive_ttl.session_lock.active_ttl_seconds` | `DAISI_WS_ADAPTIVE_TTL_SESSION_LOCK_ACTIVE_TTL_SECONDS` | Active session TTL | `30` |
| `adaptive_ttl.session_lock.inactive_ttl_seconds` | `DAISI_WS_ADAPTIVE_TTL_SESSION_LOCK_INACTIVE_TTL_SECONDS` | Inactive session TTL | `15` |

Similar settings exist for `adaptive_ttl.message_route` and `adaptive_ttl.chat_route`.

## Health Checks and Monitoring

- WebSocket service exposes HTTP health endpoints:
  - `/ready` - Readiness check
  - `/metrics` - Prometheus metrics

- Include these in Kubernetes probes:

```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 15
  periodSeconds: 10
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 20
```

## Resource Requirements

Recommended resource requests and limits for each service:

### daisi-ws-service

```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2
    memory: 1Gi
```

### message-event-service

```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2
    memory: 1Gi
```

### cdc-consumer-service

```yaml
resources:
  requests:
    cpu: 300m
    memory: 256Mi
  limits:
    cpu: 1
    memory: 512Mi
```

### sequin

```yaml
resources:
  requests:
    cpu: 500m
    memory: 768Mi
  limits:
    cpu: 2
    memory: 1.5Gi
```

### Infrastructure Services

```yaml
# PostgreSQL
resources:
  requests:
    cpu: 1
    memory: 2Gi
  limits:
    cpu: 4
    memory: 4Gi

# NATS JetStream
resources:
  requests:
    cpu: 500m
    memory: 1Gi
  limits:
    cpu: 2
    memory: 2Gi

# Redis
resources:
  requests:
    cpu: 200m
    memory: 512Mi
  limits:
    cpu: 1
    memory: 1Gi
```

## Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ws-service-hpa
  namespace: daisi
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ws-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Production Recommendations

When deploying to production, consider these additional recommendations:

1. **Secrets Management**
   - Replace all hardcoded secrets with Kubernetes Secrets
   - Use external secret management (like Vault or AWS Secrets Manager)
   - Implement proper key rotation mechanisms

2. **Network Security**
   - Implement network policies to restrict traffic between services
   - Enable TLS for all service communications
   - Use a service mesh (like Istio) for advanced traffic management

3. **High Availability**
   - Run multiple replicas of each service across different zones
   - Use StatefulSets with proper PodDisruptionBudgets
   - Configure appropriate readiness/liveness probes

4. **Backup and Disaster Recovery**
   - Configure regular PostgreSQL backups
   - Set up NATS JetStream replication
   - Test recovery procedures periodically

5. **Service Mesh**
   - Consider using a service mesh for:
     - Circuit breaking
     - Retries and timeouts
     - Traffic shifting
     - Mutual TLS

## References

- [Technical Requirements Document](./trd.md)
- [Docker Compose Configuration](../deploy/docker-compose.yaml) - Reference for local development
- [Configuration Structure](../config/config.yaml) - Default configuration options
- [Makefile Commands](../deploy/Makefile) - Local development commands
- [Sequin Configuration](../deploy/daisi-sequin.yml) - CDC configuration reference
- [PostgreSQL Setup](../deploy/setup.sql) - Database setup for replication
- [Grafana Dashboards](../deploy/grafana/dashboards/) - Monitoring dashboards