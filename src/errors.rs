use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use std::{error, fmt};

// KeyFileError
#[pyclass(extends=PyException)]
#[derive(Debug)]
pub struct KeyFileError {
    pub message: String,
}

/// Error thrown when the keyfile is corrupt, non-writable, non-readable.
#[pymethods]
impl KeyFileError {
    #[new]
    #[pyo3(signature = (message=None))]
    pub fn new(message: Option<String>) -> Self {
        let msg = message.unwrap_or_default();
        KeyFileError { message: msg }
    }

    pub fn __str__(&self) -> String {
        self.message.clone()
    }
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyFileError: {}", self.message)
    }
}

impl error::Error for KeyFileError {}

// ConfigurationError
#[pyclass(extends=PyException)]
#[derive(Debug)]
pub struct ConfigurationError {
    pub message: String,
}

/// ConfigurationError
#[pymethods]
impl ConfigurationError {
    #[new]
    #[pyo3(signature = (message=None))]
    pub fn new(message: Option<String>) -> Self {
        let msg = message.unwrap_or_default();
        ConfigurationError { message: msg }
    }

    pub fn __str__(&self) -> String {
        self.message.clone()
    }
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ConfigurationError: {}", self.message)
    }
}

impl error::Error for ConfigurationError {}

// PasswordError
#[pyclass(extends=PyException)]
#[derive(Debug)]
pub struct PasswordError {
    pub message: String,
}

/// PasswordError occurs if the password used for decryption is invalid.
#[pymethods]
impl PasswordError {
    #[new]
    #[pyo3(signature = (message=None))]
    pub fn new(message: Option<String>) -> Self {
        let msg = message.unwrap_or_default();
        PasswordError { message: msg }
    }

    pub fn __str__(&self) -> String {
        self.message.clone()
    }
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PasswordError: {}", self.message)
    }
}

impl error::Error for PasswordError {}
