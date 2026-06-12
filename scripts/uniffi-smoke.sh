#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$ROOT/target/uniffi-smoke"
LIB_DIR="$ROOT/target/debug"
LIB_PATH=""

cd "$ROOT"

cargo build -p allw-uniffi
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR/swift" "$TARGET_DIR/kotlin"

for candidate in "$LIB_DIR"/liballw_uniffi.dylib "$LIB_DIR"/liballw_uniffi.so "$LIB_DIR"/allw_uniffi.dll; do
  if [[ -f "$candidate" ]]; then
    LIB_PATH="$candidate"
    break
  fi
done
if [[ -z "$LIB_PATH" ]]; then
  echo "Could not find built allw-uniffi dynamic library in $LIB_DIR" >&2
  exit 1
fi

cargo run -p allw-uniffi --bin uniffi-bindgen -- \
  generate --library "$LIB_PATH" \
  --language swift \
  --out-dir "$TARGET_DIR/swift"

cargo run -p allw-uniffi --bin uniffi-bindgen -- \
  generate --library "$LIB_PATH" \
  --language kotlin \
  --out-dir "$TARGET_DIR/kotlin"

swiftc \
  -I "$TARGET_DIR/swift" \
  -Xcc "-fmodule-map-file=$TARGET_DIR/swift/allw_uniffiFFI.modulemap" \
  -L "$LIB_DIR" \
  -lallw_uniffi \
  "$TARGET_DIR/swift/allw_uniffi.swift" \
  "$ROOT/crates/allw-uniffi/tests/smoke.swift" \
  -o "$TARGET_DIR/swift-smoke"
DYLD_LIBRARY_PATH="$LIB_DIR" LD_LIBRARY_PATH="$LIB_DIR" "$TARGET_DIR/swift-smoke"

if command -v kotlinc >/dev/null 2>&1 && command -v java >/dev/null 2>&1; then
  JNA_JAR="${JNA_JAR:-$TARGET_DIR/jna.jar}"
  if [[ ! -f "$JNA_JAR" ]]; then
    curl --fail --location --silent --show-error \
      "https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar" \
      --output "$JNA_JAR"
  fi
  kotlinc $(find "$TARGET_DIR/kotlin" -name '*.kt' -print) "$ROOT/crates/allw-uniffi/tests/Smoke.kt" \
    -cp "$JNA_JAR" \
    -include-runtime \
    -d "$TARGET_DIR/kotlin-smoke.jar"
  # UniFFI's generated Kotlin uses JNA, which reads jna.library.path before
  # falling back to platform defaults. Keep java.library.path as a secondary
  # hint for JVMs or JNA versions that consult it.
  DYLD_LIBRARY_PATH="$LIB_DIR" LD_LIBRARY_PATH="$LIB_DIR" \
    java \
      -Djna.library.path="$LIB_DIR" \
      -Djava.library.path="$LIB_DIR" \
      -cp "$TARGET_DIR/kotlin-smoke.jar:$JNA_JAR" \
      SmokeKt
else
  echo "Skipping Kotlin smoke locally: kotlinc/java not available" >&2
fi
