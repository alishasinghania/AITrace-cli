#!/usr/bin/env bash
# Publish aitrace-cli to TestPyPI or PyPI.
#
# Usage:
#   export TWINE_USERNAME=__token__
#   export TWINE_PASSWORD='pypi-...'   # TestPyPI or PyPI token (never commit)
#   ./scripts/publish.sh testpypi     # TestPyPI
#   ./scripts/publish.sh pypi         # production PyPI
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-}"
if [[ "$TARGET" != "testpypi" && "$TARGET" != "pypi" ]]; then
  echo "Usage: $0 testpypi|pypi" >&2
  exit 2
fi

if [[ -z "${TWINE_PASSWORD:-}" ]]; then
  echo "Set TWINE_PASSWORD to your API token (username is __token__)." >&2
  echo "  export TWINE_USERNAME=__token__" >&2
  echo "  export TWINE_PASSWORD='pypi-...'" >&2
  exit 1
fi

export TWINE_USERNAME="${TWINE_USERNAME:-__token__}"

TWINE="$ROOT/.venv-build/bin/twine"
if [[ ! -x "$TWINE" ]]; then
  python3 -m venv "$ROOT/.venv-build"
  "$ROOT/.venv-build/bin/pip" install -q -U pip build twine
  TWINE="$ROOT/.venv-build/bin/twine"
fi

if [[ ! -f dist/aitrace_cli-0.1.0-py3-none-any.whl ]]; then
  echo "No dist/ wheel found. Run: .venv-build/bin/python -m build" >&2
  exit 1
fi

"$TWINE" check dist/*
if [[ "$TARGET" == "testpypi" ]]; then
  "$TWINE" upload --repository testpypi dist/*
else
  "$TWINE" upload dist/*
fi
echo "Uploaded to $TARGET."
