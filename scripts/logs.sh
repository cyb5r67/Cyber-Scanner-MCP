#!/usr/bin/env bash
# View logs from the Cybersecurity Scanner stack

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

SERVICE="${1:-mcp-server}"
docker compose logs -f "$SERVICE"
