use crate::keyfile::Keyfile;
use pyo3::prelude::*;
use sp_core::{sr25519, Pair};
use std::path::PathBuf;
const BT_WALLET_NAME: &str = "default";
pub const BT_WALLET_PATH: &str = "~/.bittensor/wallets/";

#[pyclass]
pub struct Wallet {
    name: String,
    path: PathBuf,
    keypair: sr25519::Pair,
    hotkey_str: Option<String>,
    _hotkey: Option<sr25519::Pair>,
    _coldkey: Option<sr25519::Pair>,
    _coldkeypub: Option<sr25519::Pair>,
}

#[pymethods]
impl Wallet {
    /// Creates a new Wallet instance.
    ///
    /// # Arguments
    /// * `name` - Optional wallet name. Defaults to "default".
    /// * `path` - Optional wallet path. Defaults to "~/.bittensor/wallets/".
    ///
    /// # Returns
    /// A PyResult containing the new Wallet instance.
    #[new]
    #[pyo3(signature = (name = None, path = None))]
    fn new(name: Option<String>, path: Option<String>) -> PyResult<Self> {
        let keypair = sr25519::Pair::from_string("", None)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        Ok(Wallet {
            name: name.unwrap_or_else(|| BT_WALLET_NAME.to_string()),
            path: path
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(BT_WALLET_PATH)),
            keypair,
            hotkey_str: None,
            _hotkey: None,
            _coldkey: None,
            _coldkeypub: None,
        })
    }

    /// Returns the Keyfile for the coldkey.
    ///
    /// # Returns
    /// A PyResult containing the Keyfile for the coldkey.
    #[getter]
    fn coldkey_file(&self) -> PyResult<Keyfile> {
        let wallet_path = self.wallet_path();
        let coldkey_path = wallet_path.join("coldkey");
        Ok(Keyfile::new(self.name.clone(), coldkey_path, None, None))
    }

    /// Returns the Keyfile for the coldkeypub.
    ///
    /// # Returns
    /// A PyResult containing the Keyfile for the coldkeypub.
    #[getter]
    fn coldkeypub_file(&self) -> PyResult<Keyfile> {
        let wallet_path = self.wallet_path();
        let coldkeypub_path = wallet_path.join("coldkeypub.txt");
        Ok(Keyfile::new(self.name.clone(), coldkeypub_path, None, None))
    }

    /// Returns the full path to the wallet directory.
    ///
    /// # Returns
    /// A PathBuf representing the wallet directory path.
    fn wallet_path(&self) -> PathBuf {
        self.path.join(&self.name)
    }

    /// Returns the name of the wallet.
    ///
    /// # Returns
    /// A PyResult containing the wallet name as a String.
    #[getter]
    fn name(&self) -> PyResult<String> {
        Ok(self.name.clone())
    }

    /// Returns the base path of the wallet.
    ///
    /// # Returns
    /// A PyResult containing the wallet base path as a String.
    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.path.to_string_lossy().into_owned())
    }
}
