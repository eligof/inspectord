/// Stub Rust extension module for inspectord.
///
/// eBPF process collector and other native extensions will be added
/// in subsequent PRs. This module exists to establish the build
/// infrastructure and package namespace.
use pyo3::prelude::*;

/// Entry point for the `inspectord._native` extension module.
#[pymodule]
fn _native(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}
