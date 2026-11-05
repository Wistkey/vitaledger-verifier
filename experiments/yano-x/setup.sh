#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(cd "$HERE/../.." && pwd -P)"
VERSION="0.1.0-pre4"
NAME="yano-x-jvm-$VERSION.zip"
SHA="2e35cdf12217d2f8a56587804ae9a3de8931f8e2fdb1668049a95a031507976f"
TARGET="$ROOT/.tools/yano-x-$VERSION"
for candidate in "$TARGET" "$TARGET"/*; do
  if [ -f "$candidate/yano.jar" ] && [ -x "$candidate/examples/showcase/showcase.sh" ]; then
    printf '%s\n' "$candidate"
    exit 0
  fi
done
mkdir -p "$ROOT/.tools/downloads"
ARCHIVE="$ROOT/.tools/downloads/$NAME"
if [ ! -f "$ARCHIVE" ]; then
  curl -fL --retry 3 "https://github.com/bloxbean/yano-x/releases/download/v$VERSION/$NAME" -o "$ARCHIVE.download"
  mv "$ARCHIVE.download" "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA" "$ARCHIVE" | shasum -a 256 -c -
rm -rf "$TARGET"
mkdir -p "$TARGET"
unzip -q "$ARCHIVE" -d "$TARGET"
for candidate in "$TARGET" "$TARGET"/*; do
  if [ -f "$candidate/yano.jar" ] && [ -x "$candidate/examples/showcase/showcase.sh" ]; then
    printf '%s\n' "$candidate"
    exit 0
  fi
done
printf 'Yano X archive did not contain the JVM showcase distribution\n' >&2
exit 1
