#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
VERSION="25.0.5+8"
RELEASE="25.0.5_8"
TARGET="$ROOT/.tools/jdk-$VERSION"
if [ -x "$TARGET/bin/java" ]; then
  printf '%s\n' "$TARGET"
  exit 0
fi
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) NAME="OpenJDK25U-jdk_aarch64_mac_hotspot_${RELEASE}.tar.gz"; SHA="36dc14d797aaff6d89aab302cd053fdba6207dfdcf772052fa7b023a94b0e857";;
  Linux-x86_64) NAME="OpenJDK25U-jdk_x64_linux_hotspot_${RELEASE}.tar.gz"; SHA="68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb";;
  *) printf 'unsupported local JDK platform: %s-%s; set JAVA_HOME to JDK 25\n' "$(uname -s)" "$(uname -m)" >&2; exit 1;;
esac
mkdir -p "$ROOT/.tools/downloads"
ARCHIVE="$ROOT/.tools/downloads/$NAME"
URL="https://github.com/adoptium/temurin25-binaries/releases/download/jdk-${VERSION/+/%2B}/$NAME"
if [ ! -f "$ARCHIVE" ]; then
  curl -fL --retry 3 "$URL" -o "$ARCHIVE.download"
  mv "$ARCHIVE.download" "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA" "$ARCHIVE" | shasum -a 256 -c -
TMP="$ROOT/.tools/jdk-extract-$VERSION"
rm -rf "$TMP" "$TARGET"
mkdir -p "$TMP"
tar -xzf "$ARCHIVE" -C "$TMP"
for candidate in "$TMP"/*; do
  if [ -x "$candidate/bin/java" ] || [ -x "$candidate/Contents/Home/bin/java" ]; then
    if [ -x "$candidate/Contents/Home/bin/java" ]; then candidate="$candidate/Contents/Home"; fi
    mv "$candidate" "$TARGET"
    rm -rf "$TMP"
    printf '%s\n' "$TARGET"
    exit 0
  fi
done
printf 'JDK archive did not contain a Java runtime\n' >&2
exit 1
