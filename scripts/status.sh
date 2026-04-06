#!/usr/bin/env bash
# Show status of the Cybersecurity Scanner stack

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Scanner Containers ==="
docker compose ps 2>/dev/null || echo "No containers running"

echo ""
echo "=== OB1 Integration ==="
if docker network inspect ob1_default >/dev/null 2>&1; then
    echo -e "\033[32mOB1 network: available\033[0m"
    TABLES=$(docker exec ob1-ob1-postgres-1 psql -U openbrain -d openbrain -tAc \
        "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'security';" 2>/dev/null || echo "0")
    if [ "$TABLES" -gt 0 ] 2>/dev/null; then
        echo -e "\033[32mSecurity tables: $TABLES tables in PostgreSQL\033[0m"
        SCAN_COUNT=$(docker exec ob1-ob1-postgres-1 psql -U openbrain -d openbrain -tAc \
            "SELECT COUNT(*) FROM security.scan_log;" 2>/dev/null || echo "?")
        echo "Total scans logged: $SCAN_COUNT"
    else
        echo -e "\033[33mSecurity tables: not initialized (run scripts/start.sh)\033[0m"
    fi
else
    echo -e "\033[33mOB1 network: not available (standalone mode)\033[0m"
fi

echo ""
echo "=== Recent Scans ==="
docker compose run --rm --no-deps cli history --limit 5 --json 2>/dev/null || echo "Start the scanner to view history"
