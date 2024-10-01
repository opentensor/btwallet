use pyo3::prelude::*;
use pyo3::exceptions::PyException;


#[pyclass(extends=PyException)]
pub struct KeyFileError;

/// Error thrown when the keyfile is corrupt, non-writable, non-readable or the password used to decrypt is invalid.
#[pymethods]
impl KeyFileError {
    #[new]
    pub fn new() -> Self {
        KeyFileError
    }
}

#[pyclass(extends=PyException)]
pub struct ConfigurationError;

/// Error thrown when the keyfile is corrupt, non-writable, non-readable or the password used to decrypt is invalid.
#[pymethods]
impl ConfigurationError {
    #[new]
    pub fn new() -> Self {
        ConfigurationError
    }
}
