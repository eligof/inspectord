//! Rust extension module for inspectord.

mod btf_offsets;
mod loader;
mod records;

use loader::{LoadedConnectProgram, LoadedExitProgram, LoadedProgram};
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

#[pyclass(unsendable)]
struct ProcessExitStream {
    program: Option<LoadedExitProgram>,
}

#[pymethods]
impl ProcessExitStream {
    #[new]
    fn new() -> PyResult<Self> {
        let program = LoadedExitProgram::load_and_attach()
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
            dict.set_item("comm", record.comm_str())?;
            dict.set_item("exit_code", record.exit_code)?;
            dict.set_item("exit_status", record.exit_status())?;
            dict.set_item("killed_by_signal", record.killed_by_signal())?;
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

#[pyclass(unsendable)]
struct ProcessConnectStream {
    program: Option<LoadedConnectProgram>,
}

#[pymethods]
impl ProcessConnectStream {
    #[new]
    fn new() -> PyResult<Self> {
        let program = LoadedConnectProgram::load_and_attach()
            .map_err(|e| PyOSError::new_err(format!("eBPF load failed: {e}")))?;
        Ok(Self {
            program: Some(program),
        })
    }

    /// Block for up to `timeout_ms` ms, then return all currently-available
    /// IPv4 outbound-connection records as a list of dicts. Loopback
    /// connections (either endpoint in 127.0.0.0/8) are filtered out here
    /// since they're high-volume and low-signal for a security console.
    fn poll<'py>(&mut self, py: Python<'py>, timeout_ms: u64) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let program = self
            .program
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("stream is closed"))?;
        let records = program.poll(Duration::from_millis(timeout_ms));
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            if record.is_loopback() {
                continue;
            }
            let dict = PyDict::new(py);
            dict.set_item("timestamp_ns", record.timestamp_ns)?;
            dict.set_item("pid", record.pid)?;
            dict.set_item("uid", record.uid)?;
            dict.set_item("comm", record.comm_str())?;
            dict.set_item("family", record.family)?;
            dict.set_item("saddr", record.saddr_str())?;
            dict.set_item("sport", record.sport)?;
            dict.set_item("daddr", record.daddr_str())?;
            dict.set_item("dport", record.dport())?;
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
    m.add_class::<ProcessExitStream>()?;
    m.add_class::<ProcessConnectStream>()?;
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
