use std::fmt;
use pyo3::create_exception;
use pyo3::exceptions::PyException;

#[derive(Debug)]
pub enum WalletError {
    KeyError(String),
    ConfigError(String),
    IOError(String),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::KeyError(msg) => write!(f, "Key Error: {}", msg),
            WalletError::ConfigError(msg) => write!(f, "Config Error: {}", msg),
            WalletError::IOError(msg) => write!(f, "IO Error: {}", msg),
        }
    }
}

impl std::error::Error for WalletError {}

create_exception!(wallet, WalletException, PyException);
