#!/usr/bin/env bash
# Build TrezorCore.xcframework as framework-bundle slices so it can
# coexist in one app with the other UniFFI xcframeworks (ledger-eth /
# -sol / -tron use the same approach). A flat static-lib + Headers
# xcframework emits `Headers/module.modulemap`, and a second one in the
# same app collides ("Multiple commands produce include/module.modulemap").
# Wrapping each slice in a real .framework puts the modulemap in the
# framework's own Modules/ dir, sidestepping the shared-include clash.
#
# Output:
#   ios/TrezorCore.xcframework  — drop this into Xcode
#   ios/bindings/               — generated Swift glue
#
# Prerequisites (one-time): `make setup-ios-targets`

set -euo pipefail

CRATE=trezor-core
LIB=libtrezor_core
FRAMEWORK=TrezorCore
PROFILE=release
PROFILE_DIR=release

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Prefer the rustup-managed cargo + rustc so iOS cross-compile targets
# resolve correctly (Homebrew's rustc lacks the iOS sysroots).
if command -v rustup >/dev/null 2>&1; then
    CARGO="$(rustup which cargo)"
    export RUSTC="$(rustup which rustc)"
else
    CARGO="cargo"
fi
echo "[ios] using cargo: $CARGO"
echo "[ios] using rustc: ${RUSTC:-cargo-default}"

echo "[ios] building arm64 device"
"$CARGO" build --release -p "$CRATE" --target aarch64-apple-ios

echo "[ios] building arm64 sim"
"$CARGO" build --release -p "$CRATE" --target aarch64-apple-ios-sim

echo "[ios] building x86_64 sim"
"$CARGO" build --release -p "$CRATE" --target x86_64-apple-ios

echo "[ios] creating universal simulator slice"
mkdir -p "target/universal-sim/$PROFILE_DIR"
lipo -create \
    "target/aarch64-apple-ios-sim/$PROFILE_DIR/$LIB.a" \
    "target/x86_64-apple-ios/$PROFILE_DIR/$LIB.a" \
    -output "target/universal-sim/$PROFILE_DIR/$LIB.a"

echo "[ios] generating Swift bindings"
rm -rf ios/bindings
mkdir -p ios/bindings
"$CARGO" run --release -p "$CRATE" --bin uniffi-bindgen -- \
    generate \
    --library "target/aarch64-apple-ios/$PROFILE_DIR/$LIB.a" \
    --language swift \
    --out-dir ios/bindings

SWIFT_BINDINGS="ios/bindings/trezor_core.swift"

# Swift 6 language mode rejects `public static let X: <non-Sendable>`;
# UniFFI 0.31.1's vtable pointer declarations trip this. Mark them
# `nonisolated(unsafe)` — the pointers are shared read-only at runtime.
sed -i.bak \
    -e 's/^    static let vtable:/    nonisolated(unsafe) static let vtable:/' \
    -e 's/^    static let vtablePtr:/    nonisolated(unsafe) static let vtablePtr:/' \
    "$SWIFT_BINDINGS"
rm -f "${SWIFT_BINDINGS}.bak"

# The generated glue imports the raw FFI module name; point it at the
# framework module instead so the import resolves against TrezorCore.
sed -i.bak \
    -e "s/canImport(trezor_coreFFI)/canImport($FRAMEWORK)/" \
    -e "s/import trezor_coreFFI/import $FRAMEWORK/" \
    "$SWIFT_BINDINGS"
rm -f "${SWIFT_BINDINGS}.bak"

make_framework_slice() {
    local STATIC_LIB="$1"
    local OUT_DIR="$2"
    local PLATFORM="$3"
    local FW_DIR="$OUT_DIR/$FRAMEWORK.framework"

    rm -rf "$FW_DIR"
    mkdir -p "$FW_DIR/Headers" "$FW_DIR/Modules"

    cp "$STATIC_LIB" "$FW_DIR/$FRAMEWORK"
    cp ios/bindings/*.h "$FW_DIR/Headers/"
    cat > "$FW_DIR/Modules/module.modulemap" <<MODMAP
framework module $FRAMEWORK {
    umbrella header "trezor_coreFFI.h"
    export *
    module * { export * }
}
MODMAP

    cat > "$FW_DIR/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleExecutable</key><string>$FRAMEWORK</string>
    <key>CFBundleIdentifier</key><string>com.elabify.$FRAMEWORK</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>$FRAMEWORK</string>
    <key>CFBundlePackageType</key><string>FMWK</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleSignature</key><string>????</string>
    <key>CFBundleSupportedPlatforms</key>
    <array><string>$PLATFORM</string></array>
    <key>CFBundleVersion</key><string>1</string>
</dict>
</plist>
PLIST
}

echo "[ios] wrapping device slice as framework"
mkdir -p target/framework-device
make_framework_slice \
    "target/aarch64-apple-ios/$PROFILE_DIR/$LIB.a" \
    target/framework-device \
    iPhoneOS

echo "[ios] wrapping universal sim slice as framework"
mkdir -p target/framework-sim
make_framework_slice \
    "target/universal-sim/$PROFILE_DIR/$LIB.a" \
    target/framework-sim \
    iPhoneSimulator

echo "[ios] assembling xcframework"
rm -rf "ios/$FRAMEWORK.xcframework"
xcodebuild -create-xcframework \
    -framework "target/framework-device/$FRAMEWORK.framework" \
    -framework "target/framework-sim/$FRAMEWORK.framework" \
    -output "ios/$FRAMEWORK.xcframework"

echo "[ios] done: ios/$FRAMEWORK.xcframework"
echo "[ios] Swift glue: ios/bindings/*.swift"
