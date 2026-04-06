#!/usr/bin/env bash
# Stop the Cybersecurity Scanner stack

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Stop with OB1 override if it was used
if docker compose -f docker-compose.yml -f docker-compose.ob1.yml ps --quiet 2>/dev/null | grep -q .; then
    docker compose -f docker-compose.yml -f docker-compose.ob1.yml down
else
    docker compose down
fi

echo -e "\033[32mScanner stopped.\033[0m"
