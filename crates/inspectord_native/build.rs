//! Compiles inspectord_native_bpf to bpfel-unknown-none via aya-build and
//! emits its object-file path under OUT_DIR for future include_bytes!
//! consumption from lib.rs.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "inspectord_native_bpf",
            root_dir: "../inspectord_native_bpf",
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::Nightly,
    )?;
    Ok(())
}
