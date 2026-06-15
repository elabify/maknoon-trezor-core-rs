// Wrapper binary so we can run `cargo run --bin uniffi-bindgen` to
// generate Swift / Kotlin glue from the same crate sources. This is
// the official pattern recommended by Mozilla in
// uniffi-rs/internal docs.
fn main() {
    uniffi::uniffi_bindgen_main()
}
