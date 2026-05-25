//! Rust extension module for inspectord.
//!
//! Phase 2 process_collector eBPF code will land in subsequent PRs.
//! This module currently exposes a single hello() symbol that proves
//! the maturin/PyO3 toolchain end-to-end.

use pyo3::prelude::*;

#[pyfunction]
fn hello() -> &'static str {
    "hello from inspectord_native"
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_returns_expected_string() {
        assert_eq!(hello(), "hello from inspectord_native");
    }
}
