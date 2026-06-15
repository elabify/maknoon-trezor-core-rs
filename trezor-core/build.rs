// Compile the vendored trezor-common protobufs into Rust types.
//
// Pure-Rust pipeline: `protox` parses the proto2 sources (resolving
// the custom options in options.proto and the bundled well-known
// google.protobuf.* types) into a FileDescriptorSet, which is handed
// to `prost-build`. No `protoc` system binary is required, so the
// build is reproducible and auditor-verifiable, matching the spirit
// of the ledger crates' pinned toolchain.
//
// We compile only the subset of protos this crate uses. They are
// self-contained: the per-chain message files import only
// messages-common.proto + options.proto, and messages.proto (the
// MessageType wire-number enum) imports only options.proto.
use std::path::PathBuf;

fn main() {
    let proto_dir = PathBuf::from("proto");

    let files = [
        "messages.proto",            // MessageType wire-number enum
        "messages-common.proto",     // Success / Failure / ButtonRequest / ...
        "messages-management.proto", // Initialize / Features / GetPublicKey ...
        "messages-thp.proto",        // THP channel + pairing + credential msgs
        "messages-bitcoin.proto",
        "messages-ethereum.proto",
        "messages-solana.proto",
        "messages-tron.proto",
    ];
    let paths: Vec<PathBuf> = files.iter().map(|f| proto_dir.join(f)).collect();

    let fds = protox::compile(&paths, [proto_dir.as_path()])
        .expect("protox: failed to compile vendored trezor-common protos");

    let mut cfg = prost_build::Config::new();
    // Emit a single module tree we can `include!` from one place.
    cfg.include_file("trezor_proto.rs");
    cfg.compile_fds(fds)
        .expect("prost-build: failed to generate Rust from descriptors");

    for p in &paths {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=build.rs");
}
