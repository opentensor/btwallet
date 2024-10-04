use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use pyo3::prelude::*;

#[derive(Clone)]
pub struct WalletConfig {
    pub name: String,
    pub path: String,
    pub hotkey: String,
}

impl WalletConfig {
    pub fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>) -> Self {
        WalletConfig {
            name: name.unwrap_or_else(|| BT_WALLET_NAME.to_string()),
            hotkey: hotkey.unwrap_or_else(|| BT_WALLET_HOTKEY.to_string()),
            path: path.unwrap_or_else(|| BT_WALLET_PATH.to_string()),
        }
    }
}

#[derive(Clone)]
#[pyclass(subclass)]
pub struct Config {
    pub wallet: WalletConfig,
}

#[pymethods]
impl Config {
    #[new]
    #[pyo3(signature = (name = None, hotkey = None, path = None))]
    pub fn new(
        name: Option<String>,
        hotkey: Option<String>,
        path: Option<String>,
    ) -> PyResult<Config> {
        Ok(Config {
            wallet: WalletConfig::new(name, hotkey, path),
        })
    }
    fn __str__(&self) -> PyResult<String> {
        Ok(format!(
            "Config(name: '{}', path: '~/{}', hotkey: '{}')",
            self.wallet.name, self.wallet.path, self.wallet.hotkey
        ))
    }

    fn __repr__(&self) -> PyResult<String> {
        self.__str__()
    }

    /// Returns wallet name
    #[getter]
    pub fn name(&self) -> PyResult<String> {
        Ok(self.wallet.name.clone())
    }

    /// Returns wallet name
    #[getter]
    pub fn path(&self) -> PyResult<String> {
        Ok(self.wallet.path.clone())
    }

    /// Returns wallet name
    #[getter]
    pub fn hotkey(&self) -> PyResult<String> {
        Ok(self.wallet.hotkey.clone())
    }
}
