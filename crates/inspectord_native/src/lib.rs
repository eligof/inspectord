//! Rust extension module for inspectord.
//!
//! Phase 2 process_collector entry point. PR 6 adds the aya loader;
//! the ring-buffer reader and structured records land in subsequent PRs.

mod loader;

use loader::LoadedProgram;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;

/// Python-visible handle for the loaded eBPF program.
///
/// Use as a context manager:
///
/// ```python
/// from inspectord._native import ProcessExecStream
/// with ProcessExecStream() as stream:
///     pass
/// ```
#[pyclass(unsendable)]
struct ProcessExecStream {
    program: Option<LoadedProgram>,
}

#[pymethods]
impl ProcessExecStream {
    #[new]
    fn new() -> PyResult<Self> {
        let program = LoadedProgram::load_and_attach()
            .map_err(|e| PyOSError::new_err(format!("eBPF load failed: {e}")))?;
        Ok(Self {
            program: Some(program),
        })
    }

    fn close(&mut self) {
        self.program.take();
    }

    fn __enter__<'py>(slf: PyRef<'py, Self>) -> PyRef<'py, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
        self.close();
        false
    }
}

#[pyfunction]
fn hello() -> &'static str {
    "hello from inspectord_native"
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, m)?)?;
    m.add_class::<ProcessExecStream>()?;
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
