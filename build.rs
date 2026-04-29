//! Build script.
//!
//! Two purposes:
//!
//! 1. Emits build-info (commit hash, build timestamp, rustc version) via
//!    `vergen` so `eth-historian` binaries can self-identify in logs.
//!
//! 2. Forces `vergen ~9.0` to be present in the build-dependency graph,
//!    which constrains the resolver to a version compatible with
//!    `ethportal-api 0.12.0`'s own build script. Without this, a fresh
//!    `cargo update` resolves `vergen 9.1.0` and breaks the
//!    `ethportal-api` build (incompatible `Add` trait + raised MSRV).
//!    See `Cargo.toml`'s `[build-dependencies]` comment.

fn main() {
    // Build-info; safe to ignore failures (e.g. when building outside a git
    // checkout, like a `crates.io` install).
    if let Ok(build) = vergen::BuildBuilder::all_build() {
        let _ = vergen::Emitter::default()
            .add_instructions(&build)
            .and_then(|e| {
                if let Ok(rustc) = vergen::RustcBuilder::all_rustc() {
                    e.add_instructions(&rustc).map(|e| e.clone())
                } else {
                    Ok(e.clone())
                }
            })
            .and_then(|mut e| e.emit());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
