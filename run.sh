#!/bin/bash
# Run AITrace CLI from project root. Usage: ./run.sh scan <path> [options]
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PYTHONPATH=src python3 -m aitrace_cli "$@"
