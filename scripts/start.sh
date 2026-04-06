#!/usr/bin/env bash
# Start the Cybersecurity Scanner stack
# Automatically detects and connects to OB1 if running

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Check if OB1 network exists (OB1 is running)
OB1_AVAILABLE=false
if docker network inspect ob1_default >/dev/null 2>&1; then
    OB1_AVAILABLE=true
fi

if [ "$OB1_AVAILABLE" = true ]; then
    echo -e "\033[32mOB1 detected — starting with PostgreSQL integration\033[0m"

    # Initialize security tables if they don't exist
    TABLES=$(docker exec ob1-ob1-postgres-1 psql -U openbrain -d openbrain -tAc \
        "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'security';" 2>/dev/null || echo "0")
    if [ "$TABLES" = "0" ]; then
        echo "Initializing security tables in OB1..."
        docker compose -f docker-compose.yml -f docker-compose.ob1.yml --profile init run --rm init-security-db
    fi

    docker compose -f docker-compose.yml -f docker-compose.ob1.yml up -d
else
    echo -e "\033[33mOB1 not detected — starting standalone (SQLite)\033[0m"
    docker compose up -d
fi

echo -e "\033[32mScanner started.\033[0m"
docker compose ps
