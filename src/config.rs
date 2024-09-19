use pyo3::prelude::*;
use crate::constants::{BT_WALLET_NAME, BT_WALLET_HOTKEY, BT_WALLET_PATH};


#[pyclass(name = "Config", get_all)]
#[derive(Clone)]
pub struct Config {
    pub name: String,
    pub path: String,
    pub hotkey: String,
}

#[pymethods]
impl Config {
    #[new]
    #[pyo3(signature = (name = None, hotkey = None, path = None))]
    pub fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>) -> Self {

        Config {
            name: name.unwrap_or_else(|| BT_WALLET_NAME.to_string()),
            hotkey: hotkey.unwrap_or_else(|| BT_WALLET_HOTKEY.to_string()),
            path: path.unwrap_or_else(|| BT_WALLET_PATH.to_string()),
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!(
            "Config(name: '{}', path: '{}', hotkey: '{}')",
            self.name, self.path, self.hotkey
        ))
    }

    fn __repr__(&self) -> PyResult<String> {
        self.__str__()
    }
}