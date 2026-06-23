#!/usr/bin/env bash
# Build the Android aar with native libs + generated Kotlin glue.
#
# Output:
#   android/library/build/outputs/aar/library-release.aar
#
# Prerequisites (one-time):
#   - `make setup-android-targets`
#   - Android NDK installed and ANDROID_NDK_HOME exported
#   - Android SDK with build-tools 34+

set -euo pipefail

CRATE=trezor-core
LIB=libtrezor_core

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Auto-detect ANDROID_HOME / ANDROID_NDK_HOME if not set (the
# build-system shell may not have your interactive shell's env
# sourced, e.g. when invoked from CI or a fresh make subshell).
if [[ -z "${ANDROID_HOME:-}" ]]; then
    if [[ -d "$HOME/Library/Android/sdk" ]]; then
        export ANDROID_HOME="$HOME/Library/Android/sdk"
    fi
fi
if [[ -z "${ANDROID_NDK_HOME:-}" && -d "${ANDROID_HOME:-}/ndk" ]]; then
    ANDROID_NDK_HOME="$(find "$ANDROID_HOME/ndk" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort | tail -1)"
    export ANDROID_NDK_HOME
fi
if [[ -z "${ANDROID_HOME:-}" || -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "Missing Android SDK / NDK." >&2
    echo "  ANDROID_HOME=${ANDROID_HOME:-<unset>}" >&2
    echo "  ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-<unset>}" >&2
    echo "Install via Android Studio > SDK Manager and re-run." >&2
    exit 1
fi
echo "[android] using SDK: $ANDROID_HOME"
echo "[android] using NDK: $ANDROID_NDK_HOME"

# Prefer JDK 17 if available. Gradle 8.x's bundled Kotlin compiler
# rejects Java 22+ versions (e.g. Homebrew's `openjdk` keg currently
# ships 26). 17 is the AGP-recommended baseline.
if [[ -z "${JAVA_HOME:-}" ]]; then
    for candidate in \
        "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home" \
        "/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home" \
        "/Library/Java/JavaVirtualMachines/jdk-17.0.2.jdk/Contents/Home"; do
        if [[ -d "$candidate" ]]; then
            export JAVA_HOME="$candidate"
            break
        fi
    done
fi
echo "[android] using JAVA_HOME: ${JAVA_HOME:-system default}"

# Mirror the iOS script's approach: prefer rustup-managed cargo +
# rustc so the cross-compile targets resolve correctly. Homebrew
# cargo doesn't ship Android sysroots.
if command -v rustup >/dev/null 2>&1; then
    CARGO="$(rustup which cargo)"
    export RUSTC="$(rustup which rustc)"
else
    CARGO="cargo"
fi
echo "[android] using cargo: $CARGO"
echo "[android] using rustc: ${RUSTC:-cargo-default}"

JNI_LIBS_DIR="android/library/src/main/jniLibs"
KOTLIN_OUT_DIR="android/library/src/main/java"

echo "[android] building all targets via cargo-ndk"
"$CARGO" ndk \
    --target arm64-v8a \
    --target x86_64 \
    --output-dir "$JNI_LIBS_DIR" \
    --platform 26 \
    -- build --release -p "$CRATE"

echo "[android] generating Kotlin bindings"
rm -rf "$KOTLIN_OUT_DIR/uniffi"
mkdir -p "$KOTLIN_OUT_DIR"
"$CARGO" run --release -p "$CRATE" --bin uniffi-bindgen -- \
    generate \
    --library "target/aarch64-linux-android/release/$LIB.so" \
    --language kotlin \
    --out-dir "$KOTLIN_OUT_DIR"

echo "[android] assembling aar"
cd android
./gradlew :library:assembleRelease

echo "[android] done: android/library/build/outputs/aar/library-release.aar"
