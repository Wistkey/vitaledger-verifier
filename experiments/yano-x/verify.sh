#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
if [ -z "${JAVA_HOME:-}" ]; then export JAVA_HOME="$("$ROOT/scripts/install-jdk25.sh")"; fi
export PATH="$JAVA_HOME/bin:$PATH"
DIST="$("$HERE/setup.sh")"
INSTANCE="${YANO_INSTANCE:-vitaledger-poc}"
exec "$DIST/examples/showcase/showcase.sh" verify all --instance "$INSTANCE"
