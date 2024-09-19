use pyo3::{pyclass, pymethods};

#[pyclass(name = "Keyfile", get_all)]
pub struct Keyfile {}

#[pymethods]
impl Keyfile {}
