use std::path::PathBuf;
use pyo3::{pyclass, pymethods, PyResult};

#[pyclass]
pub struct Keyfile {
    path: PathBuf,
}

#[pymethods]
impl Keyfile {
    #[new]
    fn new(path: PathBuf) -> Self {
        Keyfile { path }
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.path.to_string_lossy().into_owned())
    }
}
