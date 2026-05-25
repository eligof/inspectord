//! Rust extension module for inspectord.

mod loader;
mod records;

use loader::LoadedProgram;
use pyo3::exceptions::{PyOSError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::time::Duration;

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

    /// Block for up to `timeout_ms` ms, then return all currently-available
    /// records as a list of dicts. Empty list on timeout.
    fn poll<'py>(&mut self, py: Python<'py>, timeout_ms: u64) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let program = self
            .program
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("stream is closed"))?;
        let records = program.poll(Duration::from_millis(timeout_ms));
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let dict = PyDict::new(py);
            dict.set_item("timestamp_ns", record.timestamp_ns)?;
            dict.set_item("pid", record.pid)?;
            dict.set_item("ppid", record.ppid)?;
            dict.set_item("uid", record.uid)?;
            dict.set_item("gid", record.gid)?;
            dict.set_item("comm", record.comm_str())?;
            dict.set_item("cmdline", record.cmdline_str())?;
            out.push(dict);
        }
        Ok(out)
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
