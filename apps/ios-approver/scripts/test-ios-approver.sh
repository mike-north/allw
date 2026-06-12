#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
APP_DIR="$ROOT/apps/ios-approver"
BUILD_DIR="$ROOT/target/ios-approver-tests"
MODULE_DIR="$BUILD_DIR/module"

rm -rf "$BUILD_DIR"
mkdir -p "$MODULE_DIR"

swiftc \
  -parse-as-library \
  -emit-library \
  -emit-module \
  -module-name AllwIOSApprover \
  -emit-module-path "$MODULE_DIR/AllwIOSApprover.swiftmodule" \
  "$APP_DIR"/Sources/AllwIOSApprover/*.swift \
  -o "$BUILD_DIR/libAllwIOSApprover.dylib"

swiftc \
  -parse-as-library \
  -I "$MODULE_DIR" \
  -L "$BUILD_DIR" \
  -lAllwIOSApprover \
  "$APP_DIR"/Tests/AllwIOSApproverTests/*.swift \
  -o "$BUILD_DIR/AllwIOSApproverTests"

DYLD_LIBRARY_PATH="$BUILD_DIR" "$BUILD_DIR/AllwIOSApproverTests"
