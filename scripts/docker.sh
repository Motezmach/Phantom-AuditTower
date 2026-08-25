#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -n "${PHANTOM_IMAGE:-}" ]; then
  IMAGE_REF="$PHANTOM_IMAGE"
else
  IMAGE_REF="phantom-sandbox:${1:-1.3.0}"
fi

echo "Building $IMAGE_REF ..."
docker build \
  -f "$PROJECT_ROOT/containers/Dockerfile" \
  -t "$IMAGE_REF" \
  "$PROJECT_ROOT"

echo "Done: $IMAGE_REF"
