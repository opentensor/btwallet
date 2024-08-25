use pyo3::prelude::*;
use std::path::{Path, PathBuf};

const BT_WALLET_NAME: &str = "default";
pub const BT_WALLET_PATH: &str = "~/.bittensor/wallets/";

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

#[pyclass]
pub struct Wallet {
    name: String,
    path: PathBuf,
}

#[pymethods]
impl Wallet {
    #[new]
    #[pyo3(signature = (name = None, path = None))]
    fn new(name: Option<String>, path: Option<String>) -> PyResult<Self> {
        Ok(Wallet {
            name: name.unwrap_or_else(|| BT_WALLET_NAME.to_string()),
            path: path
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(BT_WALLET_PATH)),
        })
    }

    #[getter]
    fn coldkey_file(&self) -> PyResult<Keyfile> {
        let wallet_path = self.wallet_path();
        let coldkey_path = wallet_path.join("coldkey");
        Ok(Keyfile::new(coldkey_path))
    }

    #[getter]
    fn coldkeypub_file(&self) -> PyResult<Keyfile> {
        let wallet_path = self.wallet_path();
        let coldkeypub_path = wallet_path.join("coldkeypub.txt");
        Ok(Keyfile::new(coldkeypub_path))
    }

    fn wallet_path(&self) -> PathBuf {
        self.path.join(&self.name)
    }

    #[getter]
    fn name(&self) -> PyResult<String> {
        Ok(self.name.clone())
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.path.to_string_lossy().into_owned())
    }
}
