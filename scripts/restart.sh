#!/usr/bin/env bash
# Restart the Cybersecurity Scanner stack

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Stopping scanner..."
"$SCRIPT_DIR/stop.sh"

echo ""
echo "Starting scanner..."
"$SCRIPT_DIR/start.sh"
