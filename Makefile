.PHONY: all test fmt fmt-check clippy clean ios android setup-ios-targets setup-android-targets

# Default target: format check + clippy + test. Same gates CI runs.
all: fmt-check clippy test

test:
	cargo test --workspace --all-features

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

clean:
	cargo clean
	rm -rf ios/bindings/ ios/TrezorCore.xcframework android/jniLibs/

# iOS xcframework. Output: ./ios/TrezorCore.xcframework
ios:
	./ios/build-xcframework.sh

# Android aar. Output: ./android/build/outputs/aar/trezor-core-release.aar
android:
	./android/build-aar.sh

# One-time toolchain setup. Run once per machine.
setup-ios-targets:
	rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

setup-android-targets:
	rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
	@which cargo-ndk > /dev/null 2>&1 || cargo install cargo-ndk
