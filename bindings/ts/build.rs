// Mirrors the parent crate's vergen pin — see the parent `Cargo.toml`.
fn main() {
    if let Ok(build) = vergen::BuildBuilder::all_build() {
        let _ = vergen::Emitter::default().add_instructions(&build).and_then(|mut e| e.emit());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
