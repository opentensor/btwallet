use std::{borrow::Cow, env, str};

use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use crate::errors::{ConfigurationError, KeyFileError, PasswordError, WalletError};
use crate::keyfile;
use crate::keyfile::Keyfile as RustKeyfile;
use crate::keypair::Keypair as RustKeypair;
use crate::wallet::Wallet as RustWallet;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyBytes, PyModule, PyString, PyType};
use pyo3::wrap_pyfunction;

#[pyclass(subclass)]
#[derive(Clone)]
struct Config {
    inner: crate::config::Config,
}

#[pymethods]
impl Config {
    #[new]
    #[pyo3(signature = (name=None, hotkey=None, path=None))]
    fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>) -> Self {
        Config {
            inner: crate::config::Config::new(name, hotkey, path),
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.name()
    }

    #[getter]
    fn path(&self) -> String {
        self.inner.path()
    }

    #[getter]
    fn hotkey(&self) -> String {
        self.inner.hotkey()
    }
}

#[pyclass(name = "Keyfile", subclass)]
#[derive(Clone)]
struct PyKeyfile {
    inner: RustKeyfile,
}

#[pymethods]
impl PyKeyfile {
    #[new]
    #[pyo3(signature = (path=None, name=None, should_save_to_env=false))]
    fn new(path: Option<String>, name: Option<String>, should_save_to_env: bool) -> Self {
        PyKeyfile {
            inner: RustKeyfile::new(path.unwrap_or_default(), name, should_save_to_env)
                .expect("Failed to create keyfile"),
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
    }

    #[getter]
    fn path(&self) -> String {
        self.inner.path.clone()
    }

    fn exists_on_device(&self) -> PyResult<bool> {
        self.inner
            .exists_on_device()
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    fn is_readable(&self) -> PyResult<bool> {
        self.inner
            .is_readable()
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    fn is_writable(&self) -> PyResult<bool> {
        self.inner
            .is_writable()
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    fn is_encrypted(&self) -> PyResult<bool> {
        self.inner
            .is_encrypted()
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    #[pyo3(signature = (print_result=true, no_prompt=false))]
    fn check_and_update_encryption(&self, print_result: bool, no_prompt: bool) -> PyResult<bool> {
        self.inner
            .check_and_update_encryption(print_result, no_prompt)
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    #[pyo3(signature = (password=None))]
    fn encrypt(&self, password: Option<String>) -> PyResult<()> {
        self.inner
            .encrypt(password)
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    #[pyo3(signature = (password=None))]
    fn decrypt(&self, password: Option<String>) -> PyResult<()> {
        self.inner
            .decrypt(password)
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    fn env_var_name(&self) -> PyResult<String> {
        self.inner
            .env_var_name()
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    #[pyo3(signature = (password=None))]
    fn save_password_to_env(&self, password: Option<String>) -> PyResult<String> {
        self.inner
            .save_password_to_env(password)
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    fn remove_password_from_env(&self) -> PyResult<bool> {
        self.inner
            .remove_password_from_env()
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    #[getter(data)]
    fn data_py(&self) -> PyResult<Option<Cow<[u8]>>> {
        self.inner
            .data()
            .map(|vec| Some(Cow::Owned(vec)))
            .or_else(|_e| Ok(None))
    }

    fn make_dirs(&self) -> PyResult<()> {
        self.inner
            .make_dirs()
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
    }

    /// Returns the keypair from path, decrypts data if the file is encrypted.
    #[getter(keypair)]
    pub fn keypair_py(&self) -> PyResult<PyKeypair> {
        self.get_keypair(None)
    }

    #[pyo3(signature = (password=None))]
    fn get_keypair(&self, password: Option<String>) -> PyResult<PyKeypair> {
        self.inner
            .get_keypair(password)
            .map(|inner| PyKeypair { inner })
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
    }

    #[pyo3(signature = (keypair, encrypt=true, overwrite=false, password=None))]
    fn set_keypair(
        &self,
        keypair: PyKeypair,
        encrypt: bool,
        overwrite: bool,
        password: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .set_keypair(keypair.inner, encrypt, overwrite, password)
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
    }
}

#[pyclass(name = "Keypair", subclass)]
#[derive(Clone)]
pub struct PyKeypair {
    inner: RustKeypair,
}

#[pymethods]
impl PyKeypair {
    #[new]
    #[pyo3(signature = (ss58_address=None, public_key=None, private_key=None, ss58_format=42, seed_hex=None, crypto_type=1))]
    fn new(
        ss58_address: Option<String>,
        public_key: Option<String>,
        private_key: Option<String>,
        ss58_format: u8,
        seed_hex: Option<Vec<u8>>,
        crypto_type: u8,
    ) -> PyResult<Self> {
        let keypair = RustKeypair::new(
            ss58_address,
            public_key,
            private_key,
            ss58_format,
            seed_hex,
            crypto_type,
        )
        .map_err(|e| PyErr::new::<PyValueError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[staticmethod]
    #[pyo3(signature = (n_words=12))]
    fn generate_mnemonic(n_words: usize) -> PyResult<String> {
        RustKeypair::generate_mnemonic(n_words).map_err(|e| PyErr::new::<PyValueError, _>(e))
    }

    #[staticmethod]
    fn create_from_mnemonic(mnemonic: &str) -> PyResult<Self> {
        let keypair = RustKeypair::create_from_mnemonic(mnemonic)
            .map_err(|e| PyErr::new::<PyValueError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    /// Creates Keypair from a seed for python
    #[staticmethod]
    fn create_from_seed(py: Python, seed: &str) -> PyResult<Py<Self>> {
        let vec_seed = hex::decode(seed.trim_start_matches("0x"))
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))?;
        let keypair = RustKeypair::create_from_seed(vec_seed)
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))?;
        Py::new(py, PyKeypair { inner: keypair })
    }

    #[staticmethod]
    fn create_from_private_key(private_key: &str) -> PyResult<Self> {
        let keypair = RustKeypair::create_from_private_key(private_key)
            .map_err(|e| PyErr::new::<PyValueError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[staticmethod]
    fn create_from_encrypted_json(json_data: &str, passphrase: &str) -> PyResult<Self> {
        let keypair = RustKeypair::create_from_encrypted_json(json_data, passphrase)
            .map_err(|e| PyErr::new::<PyValueError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[staticmethod]
    fn create_from_uri(uri: &str) -> PyResult<Self> {
        let keypair =
            RustKeypair::create_from_uri(uri).map_err(|e| PyErr::new::<PyValueError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[pyo3(signature = (data))]
    fn sign(&self, data: PyObject, py: Python) -> PyResult<Cow<[u8]>> {
        // Convert data to bytes (data can be a string, hex, or bytes)
        let data_bytes = if let Ok(s) = data.extract::<String>(py) {
            if s.starts_with("0x") {
                hex::decode(s.trim_start_matches("0x")).map_err(|e| {
                    PyErr::new::<PyConfigurationError, _>(format!("Invalid hex string: {}", e))
                })?
            } else {
                s.into_bytes()
            }
        } else if let Ok(bytes) = data.extract::<Vec<u8>>(py) {
            bytes
        } else if let Ok(py_scale_bytes) = data.extract::<&PyAny>(py) {
            let scale_data: &PyAny = py_scale_bytes.getattr("data")?;
            let scale_data_bytes: Vec<u8> = scale_data.extract()?;

            scale_data_bytes.to_vec()
        } else {
            return Err(PyErr::new::<PyConfigurationError, _>(
                "Keypair::sign: Unsupported data format. Expected str or bytes.",
            ));
        };

        self.inner
            .sign(data_bytes)
            .map(Cow::from)
            .map_err(|e| PyErr::new::<PyConfigurationError, _>(e))
    }

    #[pyo3(signature = (data, signature))]
    fn verify(&self, data: PyObject, signature: PyObject, py: Python) -> PyResult<bool> {
        // Convert data to bytes (data can be a string, hex, or bytes)
        let data_bytes = if let Ok(s) = data.extract::<String>(py) {
            if s.starts_with("0x") {
                hex::decode(s.trim_start_matches("0x")).map_err(|e| {
                    PyErr::new::<PyValueError, _>(format!("Invalid hex string: {:?}", e))
                })?
            } else {
                s.into_bytes()
            }
        } else if let Ok(bytes) = data.extract::<Vec<u8>>(py) {
            bytes
        } else if let Ok(py_scale_bytes) = data.extract::<&PyAny>(py) {
            let scale_data: &PyAny = py_scale_bytes.getattr("data")?;
            let scale_data_bytes: Vec<u8> = scale_data.extract()?;

            scale_data_bytes.to_vec()
        } else {
            return Err(PyErr::new::<PyConfigurationError, _>(
                "Keypair::verify: Unsupported data format. Expected str or bytes.",
            ));
        };

        // Convert signature to bytes
        let signature_bytes = if let Ok(s) = signature.extract::<String>(py) {
            if s.starts_with("0x") {
                hex::decode(s.trim_start_matches("0x")).map_err(|e| {
                    PyErr::new::<PyValueError, _>(format!("Invalid hex string: {:?}", e))
                })?
            } else {
                return Err(PyErr::new::<PyValueError, _>(
                    "Invalid signature format. Expected hex string.",
                ));
            }
        } else if let Ok(bytes) = signature.extract::<Vec<u8>>(py) {
            bytes
        } else {
            return Err(PyErr::new::<PyValueError, _>(
                "Unsupported signature format. Expected str or bytes.",
            ));
        };

        self.inner
            .verify(data_bytes, signature_bytes)
            .map_err(|e| PyErr::new::<PyValueError, _>(e))
    }

    #[getter]
    fn ss58_address(&self) -> Option<String> {
        self.inner.ss58_address()
    }

    #[getter]
    fn public_key(&self) -> PyResult<Option<Cow<[u8]>>> {
        self.inner
            .public_key()
            .map(|opt| opt.map(Cow::from))
            .map_err(|e| PyErr::new::<PyValueError, _>(e))
    }

    #[getter]
    fn ss58_format(&self) -> u8 {
        self.inner.ss58_format()
    }

    #[getter]
    fn crypto_type(&self) -> u8 {
        self.inner.crypto_type()
    }

    #[setter]
    fn set_crypto_type(&mut self, crypto_type: u8) {
        self.inner.set_crypto_type(crypto_type)
    }
}

// Error type bindings
#[pyclass(name = "KeyFileError", extends = PyException)]
#[derive(Debug)]
pub struct PyKeyFileError {
    inner: KeyFileError,
}

#[pymethods]
impl PyKeyFileError {
    #[new]
    fn new(msg: String) -> Self {
        PyKeyFileError {
            inner: KeyFileError::Generic(msg),
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
    }
}

impl IntoPy<PyObject> for KeyFileError {
    fn into_py(self, py: Python<'_>) -> PyObject {
        Py::new(py, PyKeyFileError { inner: self })
            .unwrap()
            .into_any()
    }
}

#[pyclass(name = "ConfigurationError", extends = PyException)]
#[derive(Debug)]
pub struct PyConfigurationError {
    inner: ConfigurationError,
}

#[pymethods]
impl PyConfigurationError {
    #[new]
    fn new(msg: String) -> Self {
        PyConfigurationError {
            inner: ConfigurationError::Message(msg),
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
    }
}

#[pyclass(name = "PasswordError", extends = PyException)]
#[derive(Debug)]
pub struct PyPasswordError {
    inner: PasswordError,
}

#[pymethods]
impl PyPasswordError {
    #[new]
    fn new(msg: String) -> Self {
        PyPasswordError {
            inner: PasswordError::Message(msg),
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
    }
}

#[pyclass(name = "WalletError", extends = PyException)]
#[derive(Debug)]
pub struct PyWalletError {
    inner: WalletError,
}

#[pymethods]
impl PyWalletError {
    #[new]
    fn new(msg: String) -> Self {
        PyWalletError {
            inner: WalletError::InvalidInput(msg),
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
    }
}

impl IntoPy<PyObject> for WalletError {
    fn into_py(self, py: Python<'_>) -> PyObject {
        Py::new(py, PyWalletError { inner: self })
            .unwrap()
            .into_any()
    }
}

// Define the Python module using PyO3
#[pymodule]
fn bittensor_wallet(module: Bound<'_, PyModule>) -> PyResult<()> {
    // Add classes to the main module
    module.add_class::<Config>()?;
    module.add_class::<PyKeyfile>()?;
    module.add_class::<PyKeypair>()?;
    module.add_class::<Wallet>()?;

    // Add submodules to the main module
    register_config_module(module.clone())?;
    register_errors_module(module.clone())?;
    register_keyfile_module(module.clone())?;
    register_keypair_module(module.clone())?;
    register_utils_module(module.clone())?;
    register_wallet_module(module)?;
    Ok(())
}

// Define the submodule registration functions
fn register_config_module(main_module: Bound<'_, PyModule>) -> PyResult<()> {
    let config_module = PyModule::new_bound(main_module.py(), "config")?;
    config_module.add_class::<Config>()?;
    main_module.add_submodule(&config_module)
}

fn register_errors_module(main_module: Bound<'_, PyModule>) -> PyResult<()> {
    let errors_module = PyModule::new_bound(main_module.py(), "errors")?;
    // Register the WalletError exception
    errors_module.add_class::<PyWalletError>()?;
    errors_module.add_class::<PyConfigurationError>()?;
    errors_module.add_class::<PyKeyFileError>()?;
    errors_module.add_class::<PyPasswordError>()?;
    main_module.add_submodule(&errors_module)
}

#[pyfunction(name = "serialized_keypair_to_keyfile_data")]
#[pyo3(signature = (keypair))]
fn py_serialized_keypair_to_keyfile_data(py: Python, keypair: &PyKeypair) -> PyResult<PyObject> {
    keyfile::serialized_keypair_to_keyfile_data(&keypair.inner)
        .map(|bytes| PyBytes::new_bound(py, &bytes).into_py(py))
        .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
}

#[pyfunction(name = "deserialize_keypair_from_keyfile_data")]
fn py_deserialize_keypair_from_keyfile_data(keyfile_data: &[u8]) -> PyResult<PyKeypair> {
    keyfile::deserialize_keypair_from_keyfile_data(keyfile_data)
        .map(|inner| PyKeypair { inner })
        .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
}

#[pyfunction(name = "validate_password")]
fn py_validate_password(password: &str) -> PyResult<bool> {
    keyfile::validate_password(password).map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
}

#[pyfunction(name = "ask_password")]
fn py_ask_password(validation_required: bool) -> PyResult<String> {
    keyfile::ask_password(validation_required).map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
}

#[pyfunction(name = "legacy_encrypt_keyfile_data")]
#[pyo3(signature = (keyfile_data, password=None))]
fn py_legacy_encrypt_keyfile_data(
    keyfile_data: &[u8],
    password: Option<String>,
) -> PyResult<Vec<u8>> {
    keyfile::legacy_encrypt_keyfile_data(keyfile_data, password)
        .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
}

#[pyfunction(name = "get_password_from_environment")]
fn py_get_password_from_environment(env_var_name: String) -> PyResult<Option<String>> {
    keyfile::get_password_from_environment(env_var_name)
        .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
}

#[pyfunction(name = "encrypt_keyfile_data")]
#[pyo3(signature = (keyfile_data, password=None))]
fn py_encrypt_keyfile_data(keyfile_data: &[u8], password: Option<String>) -> PyResult<Cow<[u8]>> {
    keyfile::encrypt_keyfile_data(keyfile_data, password)
        .map(Cow::from)
        .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
}

#[pyfunction(name = "decrypt_keyfile_data")]
#[pyo3(signature = (keyfile_data, password=None, password_env_var=None))]
fn py_decrypt_keyfile_data(
    keyfile_data: &[u8],
    password: Option<String>,
    password_env_var: Option<String>,
) -> PyResult<Cow<[u8]>> {
    keyfile::decrypt_keyfile_data(keyfile_data, password, password_env_var)
        .map(Cow::from)
        .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
}

// keyfile module with functions
fn register_keyfile_module(main_module: Bound<'_, PyModule>) -> PyResult<()> {
    let keyfile_module = PyModule::new_bound(main_module.py(), "keyfile")?;
    keyfile_module.add_function(wrap_pyfunction!(
        py_serialized_keypair_to_keyfile_data,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        py_deserialize_keypair_from_keyfile_data,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(py_validate_password, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(py_ask_password, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_is_encrypted_nacl,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_is_encrypted_ansible,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_is_encrypted_legacy,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_is_encrypted,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_encryption_method,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        py_legacy_encrypt_keyfile_data,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        py_get_password_from_environment,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(py_encrypt_keyfile_data, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(py_decrypt_keyfile_data, &keyfile_module)?)?;
    keyfile_module.add_class::<PyKeyfile>()?;
    main_module.add_submodule(&keyfile_module)
}

fn register_keypair_module(main_module: Bound<'_, PyModule>) -> PyResult<()> {
    let keypair_module = PyModule::new_bound(main_module.py(), "keypair")?;
    keypair_module.add_class::<PyKeypair>()?;
    main_module.add_submodule(&keypair_module)
}

#[pyfunction(name = "get_ss58_format")]
fn py_get_ss58_format(ss58_address: &str) -> PyResult<u16> {
    crate::utils::get_ss58_format(ss58_address).map_err(|e| PyErr::new::<PyValueError, _>(e))
}

#[pyfunction(name = "is_valid_ed25519_pubkey")]
fn py_is_valid_ed25519_pubkey(public_key: &Bound<'_, PyAny>) -> PyResult<bool> {
    Python::with_gil(|_py| {
        if public_key.is_instance_of::<PyString>() {
            Ok(crate::utils::is_string_valid_ed25519_pubkey(
                public_key.extract()?,
            ))
        } else if public_key.is_instance_of::<PyBytes>() {
            Ok(crate::utils::are_bytes_valid_ed25519_pubkey(
                public_key.extract()?,
            ))
        } else {
            Err(PyErr::new::<PyValueError, _>(
                "'public_key' must be a string or bytes",
            ))
        }
    })
}

#[pyfunction(name = "is_valid_bittensor_address_or_public_key")]
fn py_is_valid_bittensor_address_or_public_key(address: &Bound<'_, PyAny>) -> bool {
    Python::with_gil(|_py| {
        if address.is_instance_of::<PyString>() {
            let Ok(address_str) = address.extract() else {
                return false;
            };
            crate::utils::is_valid_bittensor_address_or_public_key(address_str)
        } else if address.is_instance_of::<PyBytes>() {
            let Ok(address_bytes) = address.extract() else {
                return false;
            };
            let Ok(address_str) = str::from_utf8(address_bytes) else {
                return false;
            };
            crate::utils::is_valid_bittensor_address_or_public_key(address_str)
        } else {
            false
        }
    })
}

fn register_utils_module(main_module: Bound<'_, PyModule>) -> PyResult<()> {
    let utils_module = PyModule::new_bound(main_module.py(), "utils")?;
    utils_module.add_function(wrap_pyfunction!(
        crate::utils::is_valid_ss58_address,
        &utils_module
    )?)?;

    utils_module.add_function(wrap_pyfunction!(py_get_ss58_format, &utils_module)?)?;
    utils_module.add_function(wrap_pyfunction!(
        crate::utils::is_valid_ss58_address,
        &utils_module
    )?)?;
    utils_module.add_function(wrap_pyfunction!(py_is_valid_ed25519_pubkey, &utils_module)?)?;
    utils_module.add_function(wrap_pyfunction!(
        py_is_valid_bittensor_address_or_public_key,
        &utils_module
    )?)?;
    utils_module.add("SS58_FORMAT", crate::utils::SS58_FORMAT)?;
    main_module.add_submodule(&utils_module)
}

fn register_wallet_module(main_module: Bound<'_, PyModule>) -> PyResult<()> {
    let wallet_module = PyModule::new_bound(main_module.py(), "wallet")?;
    wallet_module.add_function(wrap_pyfunction!(
        crate::wallet::display_mnemonic_msg,
        &wallet_module
    )?)?;
    wallet_module.add_class::<Wallet>()?;
    main_module.add_submodule(&wallet_module)
}

fn get_attribute_string(
    py: Python,
    obj: &Bound<PyAny>,
    attr_name: &str,
) -> PyResult<Option<String>> {
    match obj.getattr(attr_name) {
        Ok(attr) => {
            if attr.is_none() {
                Ok(None)
            } else {
                let value: String = attr.extract()?;
                Ok(Some(value))
            }
        }
        Err(e) => {
            if e.is_instance_of::<pyo3::exceptions::PyAttributeError>(py) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

// Implement the Python wrappers for the Rust structs
// For example, the Wallet class:
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
        // parse python config object if passed
        let (conf_name, conf_hotkey, conf_path) = if let Some(config_obj) = config {
            let config_ref = config_obj.bind(py);

            // parse python config.wallet object if exist in config object
            match config_ref.getattr("wallet") {
                Ok(wallet_obj) if !wallet_obj.is_none() => {
                    let wallet_ref = wallet_obj.as_ref();

                    // assign values instead of default ones
                    (
                        get_attribute_string(py, wallet_ref, "name")?,
                        get_attribute_string(py, wallet_ref, "hotkey")?,
                        get_attribute_string(py, wallet_ref, "path")?,
                    )
                }
                // check if config.wallet itself was passed as config
                _ => (
                    get_attribute_string(py, config_ref, "name")?,
                    get_attribute_string(py, config_ref, "hotkey")?,
                    get_attribute_string(py, config_ref, "path")?,
                ),
            }
        } else {
            (None, None, None)
        };

        let config = crate::config::Config::new(conf_name, conf_hotkey, conf_path);
        let rust_wallet = RustWallet::new(name, hotkey, path, Some(config));
        Ok(Wallet { inner: rust_wallet })
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
    }

    /// Accept specific arguments from parser.
    #[classmethod]
    #[pyo3(signature = (parser, prefix = None))]
    pub fn add_args(
        _: &Bound<'_, PyType>,
        parser: &Bound<'_, PyAny>,
        prefix: Option<String>,
        py: Python,
    ) -> PyResult<PyObject> {
        let default_name =
            env::var("BT_WALLET_NAME").unwrap_or_else(|_| BT_WALLET_NAME.to_string());
        let default_hotkey =
            env::var("BT_WALLET_HOTKEY").unwrap_or_else(|_| BT_WALLET_HOTKEY.to_string());
        let default_path =
            env::var("BT_WALLET_PATH").unwrap_or_else(|_| BT_WALLET_PATH.to_string());

        let prefix_str = if let Some(value) = prefix {
            format!("\"{value}\"")
        } else {
            "None".to_string()
        };

        let code = format!(
            r#"
prefix = {prefix_str}
prefix_str = "" if prefix is None else prefix + "."

try:
    parser.add_argument(
        "--" + prefix_str + "wallet.name",
        required=False,
        default="{default_name}",
        help="The name of the wallet to unlock for running bittensor "
        "(name mock is reserved for mocking this wallet)",
    )
    parser.add_argument(
        "--" + prefix_str + "wallet.hotkey",
        required=False,
        default="{default_hotkey}",
        help="The name of the wallet's hotkey.",
    )
    parser.add_argument(
        "--" + prefix_str + "wallet.path",
        required=False,
        default="{default_path}",
        help="The path to your bittensor wallets",
    )
except argparse.ArgumentError:
    pass"#,
        );

        py.run_bound(
            &code,
            Some(&[("parser", parser)].into_py_dict_bound(py)),
            None,
        )?;
        Ok(parser.to_object(py))
    }

    // Wallet methods

    #[pyo3(text_signature = "($self)")]
    fn to_string(&self) -> String {
        self.inner.to_string()
    }

    #[pyo3(text_signature = "($self)")]
    fn debug_string(&self) -> String {
        format!("{:?}", self.inner)
    }

    #[pyo3(
        signature = (coldkey_use_password=Some(true), hotkey_use_password=Some(false), save_coldkey_to_env=Some(false), save_hotkey_to_env=Some(false), coldkey_password=None, hotkey_password=None, overwrite=Some(false), suppress=Some(false))
    )]
    fn create_if_non_existent(
        &mut self,
        coldkey_use_password: Option<bool>,
        hotkey_use_password: Option<bool>,
        save_coldkey_to_env: Option<bool>,
        save_hotkey_to_env: Option<bool>,
        coldkey_password: Option<String>,
        hotkey_password: Option<String>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
    ) -> PyResult<Self> {
        let result = self
            .inner
            .create_if_non_existent(
                coldkey_use_password.unwrap_or(true),
                hotkey_use_password.unwrap_or(false),
                save_coldkey_to_env.unwrap_or(false),
                save_hotkey_to_env.unwrap_or(false),
                coldkey_password,
                hotkey_password,
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
            )
            .map_err(|e| match e {
                WalletError::InvalidInput(_) | WalletError::KeyGeneration(_) => {
                    PyErr::new::<PyValueError, _>(e.to_string())
                }
                _ => PyErr::new::<PyKeyFileError, _>(format!("Failed to create wallet: {:?}", e)),
            })?;

        Ok(Wallet { inner: result })
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
    ///     Arguments:
    ///         coldkey_use_password (bool): Whether to use a password for coldkey. Defaults to ``True``.
    ///         hotkey_use_password (bool): Whether to use a password for hotkey. Defaults to ``False``.
    ///         save_coldkey_to_env (bool): Whether to save a coldkey password to local env. Defaults to ``False``.
    ///         save_hotkey_to_env (bool): Whether to save a hotkey password to local env. Defaults to ``False``.
    ///         coldkey_password (Optional[str]): Coldkey password for encryption. Defaults to ``None``. If `coldkey_password` is passed, then `coldkey_use_password` is automatically ``True``.
    ///         hotkey_password (Optional[str]): Hotkey password for encryption. Defaults to ``None``. If `hotkey_password` is passed, then `hotkey_use_password` is automatically ``True``.
    ///         overwrite (bool): Whether to overwrite an existing keys. Defaults to ``False``.
    ///         suppress (bool): If ``True``, suppresses the display of the keys mnemonic message. Defaults to ``False``.
    ///
    ///     Returns:
    ///         Wallet instance with created keys.

    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false, save_coldkey_to_env=false, save_hotkey_to_env=false, coldkey_password=None, hotkey_password=None, overwrite=false, suppress=false))]
    pub fn create(
        &mut self,
        coldkey_use_password: Option<bool>,
        hotkey_use_password: Option<bool>,
        save_coldkey_to_env: Option<bool>,
        save_hotkey_to_env: Option<bool>,
        coldkey_password: Option<String>,
        hotkey_password: Option<String>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
    ) -> PyResult<Self> {
        let result = self
            .inner
            .create(
                coldkey_use_password.unwrap_or(true),
                hotkey_use_password.unwrap_or(false),
                save_coldkey_to_env.unwrap_or(false),
                save_hotkey_to_env.unwrap_or(false),
                coldkey_password,
                hotkey_password,
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
            )
            .map_err(|e| match e {
                WalletError::InvalidInput(_) | WalletError::KeyGeneration(_) => {
                    PyErr::new::<PyValueError, _>(e.to_string())
                }
                _ => PyErr::new::<PyKeyFileError, _>(format!("Failed to create wallet: {:?}", e)),
            })?;

        Ok(Wallet { inner: result })
    }

    #[pyo3(
        signature = (coldkey_use_password=Some(true), hotkey_use_password=Some(false), save_coldkey_to_env=Some(false), save_hotkey_to_env=Some(false), coldkey_password=None, hotkey_password=None, overwrite=Some(false), suppress=Some(false))
    )]
    fn recreate(
        &mut self,
        coldkey_use_password: Option<bool>,
        hotkey_use_password: Option<bool>,
        save_coldkey_to_env: Option<bool>,
        save_hotkey_to_env: Option<bool>,
        coldkey_password: Option<String>,
        hotkey_password: Option<String>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
    ) -> PyResult<Self> {
        let result = self
            .inner
            .recreate(
                coldkey_use_password.unwrap_or(true),
                hotkey_use_password.unwrap_or(false),
                save_coldkey_to_env.unwrap_or(false),
                save_hotkey_to_env.unwrap_or(false),
                coldkey_password,
                hotkey_password,
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
            )
            .map_err(|e| match e {
                WalletError::InvalidInput(_) | WalletError::KeyGeneration(_) => {
                    PyErr::new::<PyValueError, _>(e.to_string())
                }
                _ => PyErr::new::<PyKeyFileError, _>(format!("Failed to recreate wallet: {:?}", e)),
            })?;

        Ok(Wallet { inner: result })
    }

    #[pyo3(signature = (password=None))]
    fn get_coldkey(&self, password: Option<String>) -> PyResult<PyKeypair> {
        let keypair = self
            .inner
            .get_coldkey(password)
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[pyo3(signature = (password=None))]
    fn get_coldkeypub(&self, password: Option<String>) -> PyResult<PyKeypair> {
        let keypair = self
            .inner
            .get_coldkeypub(password)
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[pyo3(signature = (password=None))]
    fn get_hotkey(&self, password: Option<String>) -> PyResult<PyKeypair> {
        let keypair = self
            .inner
            .get_hotkey(password)
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[pyo3(signature = (keypair, encrypt=true, overwrite=false, save_coldkey_to_env=false, coldkey_password=None))]
    fn set_coldkey(
        &mut self,
        keypair: PyKeypair,
        encrypt: bool,
        overwrite: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .set_coldkey(
                keypair.inner,
                encrypt,
                overwrite,
                save_coldkey_to_env,
                coldkey_password,
            )
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
    }

    #[pyo3(signature = (keypair, encrypt=false, overwrite=false))]
    fn set_coldkeypub(
        &mut self,
        keypair: PyKeypair,
        encrypt: bool,
        overwrite: bool,
    ) -> PyResult<()> {
        self.inner
            .set_coldkeypub(keypair.inner, encrypt, overwrite)
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
    }

    #[pyo3(signature = (keypair, encrypt=false, overwrite=false, save_hotkey_to_env=false, hotkey_password=None))]
    fn set_hotkey(
        &mut self,
        keypair: PyKeypair,
        encrypt: bool,
        overwrite: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .set_hotkey(
                keypair.inner,
                encrypt,
                overwrite,
                save_hotkey_to_env,
                hotkey_password,
            )
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
    }

    // Getters
    #[getter(coldkey)]
    fn coldkey_py_property(&self) -> PyResult<PyKeypair> {
        let keypair = self.inner.coldkey_property().map_err(|e| {
            PyErr::new::<PyKeyFileError, _>(format!("Failed to get coldkey: {:?}", e))
        })?;
        Ok(PyKeypair { inner: keypair })
    }

    #[getter(coldkeypub)]
    fn coldkeypub_py_property(&self) -> PyResult<PyKeypair> {
        let keypair = self.inner.coldkeypub_property().map_err(|e| {
            PyErr::new::<PyKeyFileError, _>(format!("Failed to get coldkeypub: {:?}", e))
        })?;
        Ok(PyKeypair { inner: keypair })
    }

    #[getter(hotkey)]
    fn hotkey_py_property(&self) -> PyResult<PyKeypair> {
        let keypair = self.inner.hotkey_property().map_err(|e| {
            PyErr::new::<PyKeyFileError, _>(format!("Failed to get hotkey: {:?}", e))
        })?;
        Ok(PyKeypair { inner: keypair })
    }

    #[getter]
    fn coldkey_file(&self) -> PyResult<PyKeyfile> {
        self.inner
            .coldkey_file()
            .map(|inner| PyKeyfile { inner })
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
    }

    #[getter]
    fn coldkeypub_file(&self) -> PyResult<PyKeyfile> {
        self.inner
            .coldkeypub_file()
            .map(|inner| PyKeyfile { inner })
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
    }

    #[getter]
    fn hotkey_file(&self) -> PyResult<PyKeyfile> {
        self.inner
            .hotkey_file()
            .map(|inner| PyKeyfile { inner })
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.get_name()
    }

    #[getter]
    fn path(&self) -> String {
        self.inner.get_path()
    }

    #[getter]
    fn hotkey_str(&self) -> String {
        self.inner.get_hotkey_str()
    }

    #[pyo3(
        signature = (uri, use_password=false, overwrite=false, suppress=true, save_coldkey_to_env=false, coldkey_password=None)
    )]
    fn create_coldkey_from_uri(
        &mut self,
        uri: String,
        use_password: Option<bool>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
        save_coldkey_to_env: Option<bool>,
        coldkey_password: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .create_coldkey_from_uri(
                uri,
                use_password.unwrap_or(true),
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
                save_coldkey_to_env.unwrap_or(false),
                coldkey_password,
            )
            .map(|_| ())
            .map_err(|e| {
                PyErr::new::<PyKeyFileError, _>(format!(
                    "Failed to create coldkey from uri: {:?}",
                    e
                ))
            })
    }

    #[pyo3(
        signature = (uri, use_password=false, overwrite=false, suppress=true, save_hotkey_to_env=false, hotkey_password=None)
    )]
    fn create_hotkey_from_uri(
        &mut self,
        uri: String,
        use_password: Option<bool>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
        save_hotkey_to_env: Option<bool>,
        hotkey_password: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .create_hotkey_from_uri(
                uri,
                use_password.unwrap_or(true),
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
                save_hotkey_to_env.unwrap_or(false),
                hotkey_password,
            )
            .map(|_| ())
            .map_err(|e| {
                PyErr::new::<PyKeyFileError, _>(format!(
                    "Failed to create hotkey from uri: {:?}",
                    e
                ))
            })
    }

    #[pyo3(text_signature = "($self)")]
    fn unlock_coldkey(&mut self) -> PyResult<PyKeypair> {
        self.inner
            .unlock_coldkey()
            .map(|inner| PyKeypair { inner })
            .map_err(|e| match e {
                KeyFileError::DecryptionError(_) => PyErr::new::<PyPasswordError, _>(format!(
                    "Decryption failed: {}",
                    e.to_string()
                )),
                _ => PyErr::new::<PyKeyFileError, _>(format!("Keyfile error: {:?}", e)),
            })
    }

    #[pyo3(text_signature = "($self)")]
    fn unlock_coldkeypub(&mut self) -> PyResult<PyKeypair> {
        self.inner
            .unlock_coldkeypub()
            .map(|inner| PyKeypair { inner })
            .map_err(|e| match e {
                KeyFileError::DecryptionError(_) => PyErr::new::<PyPasswordError, _>(format!(
                    "Decryption failed: {}",
                    e.to_string()
                )),
                _ => PyErr::new::<PyKeyFileError, _>(format!("Failed to unlock coldkey: {:?}", e)),
            })
    }

    #[pyo3(text_signature = "($self)")]
    fn unlock_hotkey(&mut self) -> PyResult<PyKeypair> {
        self.inner
            .unlock_hotkey()
            .map(|inner| PyKeypair { inner })
            .map_err(|e| match e {
                KeyFileError::DecryptionError(_) => PyErr::new::<PyPasswordError, _>(format!(
                    "Decryption failed: {}",
                    e.to_string()
                )),
                _ => PyErr::new::<PyKeyFileError, _>(format!("Failed to unlock hotkey: {:?}", e)),
            })
    }

    #[pyo3(
        name = "create_new_coldkey",
        signature = (n_words=Some(12), use_password=None, overwrite=None, suppress=None, save_coldkey_to_env=None, coldkey_password=None)
    )]
    fn new_coldkey(
        &mut self,
        n_words: Option<usize>,
        use_password: Option<bool>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
        save_coldkey_to_env: Option<bool>,
        coldkey_password: Option<String>,
    ) -> PyResult<Self> {
        self.inner
            .new_coldkey(
                n_words.unwrap_or(12),
                use_password.unwrap_or(true),
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
                save_coldkey_to_env.unwrap_or(false),
                coldkey_password,
            )
            .map(|inner| Wallet { inner })
            .map_err(|e| {
                PyErr::new::<PyKeyFileError, _>(format!("Failed to create new coldkey: {:?}", e))
            })
    }

    #[pyo3(
        name = "create_new_hotkey",
        signature = (n_words=Some(12), use_password=None, overwrite=None, suppress=None, save_hotkey_to_env=None, hotkey_password=None)
    )]
    fn new_hotkey(
        &mut self,
        n_words: Option<usize>,
        use_password: Option<bool>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
        save_hotkey_to_env: Option<bool>,
        hotkey_password: Option<String>,
    ) -> PyResult<Self> {
        self.inner
            .new_hotkey(
                n_words.unwrap_or(12),
                use_password.unwrap_or(true),
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
                save_hotkey_to_env.unwrap_or(false),
                hotkey_password,
            )
            .map(|inner| Wallet { inner })
            .map_err(|e| {
                PyErr::new::<PyKeyFileError, _>(format!("Failed to create new hotkey: {:?}", e))
            })
    }

    #[pyo3(signature = (
        mnemonic=None,
        seed=None,
        json=None,
        use_password=true,
        overwrite=false,
        suppress=false,
        save_coldkey_to_env=false,
        coldkey_password=None
    ))]
    fn regenerate_coldkey(
        &mut self,
        mnemonic: Option<String>,
        seed: Option<String>,
        json: Option<(String, String)>,
        use_password: Option<bool>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
        save_coldkey_to_env: Option<bool>,
        coldkey_password: Option<String>,
    ) -> PyResult<()> {
        let new_inner_wallet = self
            .inner
            .regenerate_coldkey(
                mnemonic,
                seed,
                json,
                use_password.unwrap_or(true),
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
                save_coldkey_to_env.unwrap_or(false),
                coldkey_password,
            )
            .map_err(|e| match e {
                WalletError::InvalidInput(_) | WalletError::KeyGeneration(_) => {
                    PyErr::new::<PyValueError, _>(e.to_string())
                }
                _ => PyErr::new::<PyKeyFileError, _>(e.to_string()),
            })?;
        self.inner = new_inner_wallet;
        Ok(())
    }

    #[pyo3(signature = (ss58_address=None, public_key=None, overwrite=None))]
    fn regenerate_coldkeypub(
        &mut self,
        ss58_address: Option<String>,
        public_key: Option<String>,
        overwrite: Option<bool>,
    ) -> PyResult<()> {
        let new_inner_wallet = self
            .inner
            .regenerate_coldkeypub(ss58_address, public_key, overwrite.unwrap_or(false))
            .map_err(|e| PyErr::new::<PyKeyFileError, _>(e))?;
        self.inner = new_inner_wallet;
        Ok(())
    }

    #[pyo3(signature = (
        mnemonic=None,
        seed=None,
        json=None,
        use_password=false,
        overwrite=false,
        suppress=false,
        save_hotkey_to_env=false,
        hotkey_password=None
    ))]
    fn regenerate_hotkey(
        &mut self,
        mnemonic: Option<String>,
        seed: Option<String>,
        json: Option<(String, String)>,
        use_password: Option<bool>,
        overwrite: Option<bool>,
        suppress: Option<bool>,
        save_hotkey_to_env: Option<bool>,
        hotkey_password: Option<String>,
    ) -> PyResult<()> {
        let new_inner_wallet = self
            .inner
            .regenerate_hotkey(
                mnemonic,
                seed,
                json,
                use_password.unwrap_or(false),
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
                save_hotkey_to_env.unwrap_or(false),
                hotkey_password,
            )
            .map_err(|e| {
                PyErr::new::<PyKeyFileError, _>(format!("Failed to regenerate hotkey: {:?}", e))
            })?;
        self.inner = new_inner_wallet;
        Ok(())
    }
}
