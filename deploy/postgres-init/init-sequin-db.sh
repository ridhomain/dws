#!/bin/bash
# This script is run when the Postgres container starts for the first time.
# It creates the dedicated database required by the Sequin service.

set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE sequin_db;
    GRANT ALL PRIVILEGES ON DATABASE sequin_db TO "$POSTGRES_USER";
    \connect sequin_db "$POSTGRES_USER"
    -- You can add any Sequin-specific extensions or initial schema setup here if needed.
    -- For example: CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EOSQL

echo "Database 'sequin_db' created and configured for user '$POSTGRES_USER'" 