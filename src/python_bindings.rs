use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyModule, PyString, PyType};
use std::path::PathBuf;

use crate::config::Config as RustConfig;
use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use crate::errors::{ConfigurationError, KeyFileError};
use crate::keyfile::Keyfile as RustKeyfile;
use crate::keypair::Keypair as RustKeypair;
use crate::utils;
use crate::wallet::Wallet as RustWallet;

/// Python wrapper for the `Wallet` struct
#[pyclass(subclass)]
pub struct Wallet {
    pub inner: RustWallet,
}

#[pymethods]
impl Wallet {
    #[new]
    #[pyo3(signature = (name=None, hotkey=None, path=None, config=None))]
    fn new(
        name: Option<String>,
        hotkey: Option<String>,
        path: Option<String>,
        config: Option<PyObject>,
        py: Python,
    ) -> PyResult<Self> {
        // Handle config conversion
        let rust_config = match config {
            Some(cfg) => {
                let cfg_dict: &PyDict = cfg.extract(py)?;
                let wallet_dict = cfg_dict.get_item("wallet");
                let wallet_config = if let Some(wallet) = wallet_dict {
                    let wallet = wallet.downcast::<PyDict>()?;
                    let cfg_name: Option<String> =
                        wallet.get_item("name").and_then(|v| v.extract().ok());
                    let cfg_hotkey: Option<String> =
                        wallet.get_item("hotkey").and_then(|v| v.extract().ok());
                    let cfg_path: Option<String> =
                        wallet.get_item("path").and_then(|v| v.extract().ok());
                    Some(RustConfig::new(cfg_name, cfg_hotkey, cfg_path).unwrap())
                } else {
                    None
                };
                wallet_config
            }
            None => None,
        };

        let rust_wallet = RustWallet::new(name, hotkey, path, rust_config.map(|c| c.wallet))
            .map_err(|e| {
                PyErr::new::<PyException, _>(format!("Failed to create Wallet: {:?}", e))
            })?;
        Ok(Wallet { inner: rust_wallet })
    }

    #[getter]
    fn name(&self) -> PyResult<String> {
        Ok(self.inner.name.clone())
    }

    #[getter]
    fn hotkey(&self) -> PyResult<String> {
        Ok(self.inner.hotkey.clone())
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.inner.path.clone())
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!(
            "Wallet (Name: '{}', Hotkey: '{}', Path: '{}')",
            self.inner.name, self.inner.hotkey, self.inner.path
        ))
    }

    fn __repr__(&self) -> PyResult<String> {
        self.__str__()
    }

    /// Returns the default configuration for the wallet.
    #[classmethod]
    fn config(_cls: &PyType) -> PyResult<Config> {
        Ok(Config {
            inner: RustConfig::new(None, None, None),
        })
    }

    /// Adds arguments to an argparse parser.
    #[classmethod]
    #[pyo3(signature = (parser, prefix=None))]
    fn add_args(
        _cls: &PyType,
        parser: &PyAny,
        prefix: Option<String>,
        py: Python,
    ) -> PyResult<&PyAny> {
        let default_name =
            std::env::var("BT_WALLET_NAME").unwrap_or_else(|_| BT_WALLET_NAME.to_string());
        let default_hotkey =
            std::env::var("BT_WALLET_HOTKEY").unwrap_or_else(|_| BT_WALLET_HOTKEY.to_string());
        let default_path =
            std::env::var("BT_WALLET_PATH").unwrap_or_else(|_| BT_WALLET_PATH.to_string());

        let prefix_str = prefix.map_or_else(|| "".to_string(), |p| format!("{}.", p));

        let add_argument = |arg_name: &str, default: &str, help: &str| -> PyResult<()> {
            parser.call_method1(
                "add_argument",
                (
                    format!("--{}wallet.{}", prefix_str, arg_name),
                    PyDict::new(py).items(&[
                        ("required", false.into_py(py)),
                        ("default", default.into_py(py)),
                        ("help", help.into_py(py)),
                    ]),
                ),
            )?;
            Ok(())
        };

        add_argument(
            "name",
            &default_name,
            "The name of the wallet to unlock for running bittensor.",
        )?;
        add_argument(
            "hotkey",
            &default_hotkey,
            "The name of the wallet's hotkey.",
        )?;
        add_argument("path", &default_path, "The path to your bittensor wallets.")?;

        Ok(parser)
    }

    /// Other methods wrapping the Rust `Wallet` methods
    fn create_if_non_existent(
        &mut self,
        coldkey_use_password: bool,
        hotkey_use_password: bool,
        save_coldkey_to_env: bool,
        save_hotkey_to_env: bool,
        coldkey_password: Option<String>,
        hotkey_password: Option<String>,
        overwrite: bool,
        suppress: bool,
        py: Python,
    ) -> PyResult<Self> {
        self.inner
            .create_if_non_existent(
                coldkey_use_password,
                hotkey_use_password,
                save_coldkey_to_env,
                save_hotkey_to_env,
                coldkey_password,
                hotkey_password,
                overwrite,
                suppress,
                py,
            )
            .map_err(|e| PyErr::new::<PyException, _>(format!("{:?}", e)))?;
        Ok(self.clone())
    }

    fn unlock_coldkey(&mut self, py: Python) -> PyResult<Keypair> {
        let keypair = self
            .inner
            .unlock_coldkey(py)
            .map_err(|e| PyErr::new::<PyException, _>(format!("{:?}", e)))?;
        Ok(Keypair { inner: keypair })
    }

    fn unlock_hotkey(&mut self, py: Python) -> PyResult<Keypair> {
        let keypair = self
            .inner
            .unlock_hotkey(py)
            .map_err(|e| PyErr::new::<PyException, _>(format!("{:?}", e)))?;
        Ok(Keypair { inner: keypair })
    }

    // Add other methods as needed, mapping to `self.inner` methods
}

/// Python wrapper for the `Config` struct
#[pyclass(subclass)]
pub struct Config {
    inner: RustConfig,
}
#[pymethods]
impl Config {
    #[new]
    #[pyo3(signature = (name=None, hotkey=None, path=None))]
    fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>) -> PyResult<Self> {
        Ok(Config {
            inner: RustConfig::new(name, hotkey, path)?,
        })
    }

    #[getter]
    fn name(&self) -> PyResult<String> {
        Ok(self.inner.name()?)
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.inner.path()?)
    }

    #[getter]
    fn hotkey(&self) -> PyResult<String> {
        Ok(self.inner.hotkey()?)
    }

    fn __str__(&self) -> PyResult<String> {
        self.inner.__str__()
    }

    fn __repr__(&self) -> PyResult<String> {
        self.inner.__repr__()
    }

    // TODO: Add validation for name, path and hotkey
    // TODO: Add setters for name, path and hotkey
    // TODO: Add methods to save/load config from file
    // TODO: Add methods to validate config
}

/// Python wrapper for the `Keypair` struct
#[pyclass(subclass)]
pub struct Keypair {
    pub inner: RustKeypair,
}

#[pymethods]
impl Keypair {
    #[new]
    #[pyo3(signature = (ss58_address = None, public_key = None, private_key = None, ss58_format = 42, seed_hex = None, crypto_type = 1))]
    fn new(
        ss58_address: Option<String>,
        public_key: Option<String>, 
        private_key: Option<String>,
        ss58_format: u8,
        seed_hex: Option<Vec<u8>>,
        crypto_type: u8,
    ) -> PyResult<Self> {
        Ok(Keypair {
            inner: RustKeypair::new(ss58_address, public_key, private_key, ss58_format, seed_hex, crypto_type)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (n_words = 12))]
    fn generate_mnemonic(n_words: usize) -> PyResult<String> {
        RustKeypair::generate_mnemonic(n_words)
    }

    #[staticmethod]
    #[pyo3(signature = (mnemonic))]
    fn create_from_mnemonic(mnemonic: &str) -> PyResult<Self> {
        Ok(Keypair {
            inner: RustKeypair::create_from_mnemonic(mnemonic)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (seed_hex))]
    fn create_from_seed(seed_hex: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Keypair {
            inner: RustKeypair::create_from_seed(seed_hex)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (private_key))]
    fn create_from_private_key(private_key: &str) -> PyResult<Self> {
        Ok(Keypair {
            inner: RustKeypair::create_from_private_key(private_key)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (json_data, passphrase))]
    fn create_from_encrypted_json(json_data: &str, passphrase: &str) -> PyResult<Self> {
        Ok(Keypair {
            inner: RustKeypair::create_from_encrypted_json(json_data, passphrase)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (uri))]
    fn create_from_uri(uri: &str) -> PyResult<Self> {
        Ok(Keypair {
            inner: RustKeypair::create_from_uri(uri)?,
        })
    }

    #[pyo3(signature = (data))]
    fn sign(&self, data: PyObject, py: Python) -> PyResult<PyObject> {
        self.inner.sign(data, py)
    }

    #[pyo3(signature = (data, signature))]
    fn verify(&self, data: PyObject, signature: PyObject, py: Python) -> PyResult<bool> {
        self.inner.verify(data, signature, py)
    }

    #[getter]
    fn ss58_address(&self) -> PyResult<Option<String>> {
        self.inner.ss58_address()
    }

    #[getter]
    fn public_key(&self, py: Python) -> PyResult<Option<PyObject>> {
        self.inner.public_key(py)
    }

    #[getter]
    fn ss58_format(&self) -> PyResult<u8> {
        self.inner.ss58_format()
    }

    #[getter]
    fn seed_hex(&self, py: Python) -> PyResult<Option<PyObject>> {
        self.inner.seed_hex(py)
    }

    #[getter]
    fn crypto_type(&self) -> PyResult<u8> {
        self.inner.crypto_type()
    }

    #[getter]
    fn mnemonic(&self) -> PyResult<Option<String>> {
        self.inner.mnemonic()
    }

    fn __str__(&self) -> PyResult<String> {
        self.inner.__str__()
    }

    fn __repr__(&self) -> PyResult<String> {
        self.inner.__repr__()
    }
}

/// Python wrapper for the `Keyfile` struct
#[pyclass(subclass)]
pub struct Keyfile {
    pub inner: RustKeyfile,
}

#[pymethods]
impl Keyfile {
    #[new]
    fn new(path: String) -> PyResult<Self> {
        Ok(Keyfile {
            inner: RustKeyfile::new(PathBuf::from(path)),
        })
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.inner.path.to_string_lossy().into_owned())
    }

    fn exists_on_device(&self) -> PyResult<bool> {
        self.inner.exists_on_device()
    }

    fn is_readable(&self) -> PyResult<bool> {
        self.inner.is_readable()
    }

    fn is_writable(&self) -> PyResult<bool> {
        self.inner.is_writable()
    }

    fn is_encrypted(&self, py: Python) -> PyResult<bool> {
        self.inner.is_encrypted(py)
    }

    #[pyo3(signature = (print_result = true, no_prompt = false))]
    fn check_and_update_encryption(&self, print_result: bool, no_prompt: bool, py: Python) -> PyResult<bool> {
        self.inner.check_and_update_encryption(print_result, no_prompt, py)
    }

    #[pyo3(signature = (password = None))]
    fn encrypt(&self, password: Option<String>, py: Python) -> PyResult<()> {
        self.inner.encrypt(password, py)
    }

    #[pyo3(signature = (password = None))]
    fn decrypt(&self, password: Option<String>, py: Python) -> PyResult<()> {
        self.inner.decrypt(password, py)
    }

    fn _read_keyfile_data_from_file(&self, py: Python) -> PyResult<PyObject> {
        self.inner._read_keyfile_data_from_file(py)
    }

    #[pyo3(signature = (keyfile_data, overwrite = false))]
    fn _write_keyfile_data_to_file(&self, keyfile_data: &[u8], overwrite: bool) -> PyResult<()> {
        self.inner._write_keyfile_data_to_file(keyfile_data, overwrite)
    }

    #[pyo3(signature = (password = None))]
    fn save_password_to_env(&self, password: Option<String>, py: Python) -> PyResult<String> {
        self.inner.save_password_to_env(password, py)
    }

    fn remove_password_from_env(&self) -> PyResult<bool> {
        self.inner.remove_password_from_env()
    }
}

/// Display the mnemonic and a warning message to keep the mnemonic safe.
#[pyfunction]
#[pyo3(signature = (mnemonic, key_type))]
fn display_mnemonic_msg(mnemonic: String, key_type: &str) {
    utils::print(format!(
        "\nIMPORTANT: Store this mnemonic in a secure (preferably offline) place, as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.\n"
    ));

    utils::print(format!(
        "\nThe mnemonic to the new {} is: {}\n",
        key_type, mnemonic
    ));
}

#[pymodule]
pub fn python_bindings(py: Python<'_>, module: &PyModule) -> PyResult<()> {
    // Register classes
    module.add_class::<Wallet>()?;
    module.add_class::<Keypair>()?;
    module.add_class::<Keyfile>()?;
    module.add_class::<Config>()?;

    // Register functions
    module.add_function(wrap_pyfunction!(display_mnemonic_msg, module)?)?;

    // Add other functions or submodules as needed
    Ok(())
}
