#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
VERSION="3.9.11"
TARGET="$ROOT/.tools/apache-maven-$VERSION"
if [ -x "$TARGET/bin/mvn" ]; then
  printf '%s\n' "$TARGET"
  exit 0
fi
NAME="apache-maven-$VERSION-bin.tar.gz"
ARCHIVE="$ROOT/.tools/downloads/$NAME"
SHA="bcfe4fe305c962ace56ac7b5fc7a08b87d5abd8b7e89027ab251069faebee516b0ded8961445d6d91ec1985dfe30f8153268843c89aa392733d1a3ec956c9978"
mkdir -p "$ROOT/.tools/downloads"
if [ ! -f "$ARCHIVE" ]; then
  curl -fL --retry 3 "https://archive.apache.org/dist/maven/maven-3/$VERSION/binaries/$NAME" -o "$ARCHIVE.download"
  mv "$ARCHIVE.download" "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA" "$ARCHIVE" | shasum -a 512 -c -
rm -rf "$TARGET"
tar -xzf "$ARCHIVE" -C "$ROOT/.tools"
printf '%s\n' "$TARGET"
