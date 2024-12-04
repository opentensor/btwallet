use core::str;
use std::borrow::Cow;

use crate::errors::{ConfigurationError, KeyFileError, PasswordError};
use crate::keyfile;
use crate::keyfile::Keyfile as RustKeyfile;
use crate::keypair::Keypair as RustKeypair;
use crate::utils::is_valid_ss58_address;
use crate::wallet::Wallet as RustWallet;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule, PyString, PyTuple, PyType};
use pyo3::wrap_pyfunction;
use pyo3::{create_exception, ffi};

#[pyclass]
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

#[pyclass(name = "Keyfile")]
#[derive(Clone)]
struct PyKeyfile {
    inner: RustKeyfile,
}

#[pymethods]
impl PyKeyfile {
    #[new]
    #[pyo3(signature = (path=None, name=None, should_save_to_env=true))]
    fn new(path: Option<String>, name: Option<String>, should_save_to_env: bool) -> Self {
        PyKeyfile {
            inner: RustKeyfile::new(path.unwrap_or_default(), name, should_save_to_env)
                .expect("Failed to create keyfile"),
        }
    }

    fn __str__(&self) -> PyResult<String> {
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
    fn generate_mnemonic(n_words: usize) -> PyResult<String> {
        RustKeypair::generate_mnemonic(n_words).map_err(|e| PyErr::new::<PyValueError, _>(e))
    }

    #[staticmethod]
    fn create_from_mnemonic(mnemonic: &str) -> PyResult<Self> {
        let keypair = RustKeypair::create_from_mnemonic(mnemonic)
            .map_err(|e| PyErr::new::<PyValueError, _>(e))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[staticmethod]
    fn create_from_seed(py: Python, seed: Vec<u8>) -> PyResult<Py<Self>> {
        let keypair =
            RustKeypair::create_from_seed(seed).map_err(|e| PyErr::new::<PyValueError, _>(e))?;
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

    fn sign(&self, data: Vec<u8>) -> PyResult<Vec<u8>> {
        self.inner
            .sign(data)
            .map_err(|e| PyErr::new::<PyValueError, _>(e))
    }

    fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        self.inner
            .verify(data, signature)
            .map_err(|e| PyErr::new::<PyValueError, _>(e))
    }

    #[getter]
    fn ss58_address(&self) -> Option<String> {
        self.inner.ss58_address()
    }

    #[getter]
    fn public_key(&self) -> PyResult<Option<Vec<u8>>> {
        self.inner
            .public_key()
            .map_err(|e| PyErr::new::<PyValueError, _>(e))
    }

    #[getter]
    fn ss58_format(&self) -> u8 {
        self.inner.ss58_format()
    }

    #[getter]
    fn seed_hex(&self) -> Option<Vec<u8>> {
        self.inner.seed_hex()
    }

    #[getter]
    fn crypto_type(&self) -> u8 {
        self.inner.crypto_type()
    }

    #[setter]
    fn set_crypto_type(&mut self, crypto_type: u8) {
        self.inner.set_crypto_type(crypto_type)
    }

    #[getter]
    fn mnemonic(&self) -> Option<String> {
        self.inner.mnemonic()
    }

    #[getter]
    fn private_key(&self) -> PyResult<Option<Vec<u8>>> {
        self.inner
            .private_key()
            .map_err(|e| PyErr::new::<PyValueError, _>(e))
    }
}

// Error type bindings
#[pyclass(name = "KeyFileError")]
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

#[pyclass(name = "ConfigurationError")]
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

#[pyclass(name = "PasswordError")]
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

create_exception!(errors, WalletError, PyException);

// Define the Python module using PyO3
#[pymodule]
fn bittensor_wallet(py: Python<'_>, module: Bound<'_, PyModule>) -> PyResult<()> {
    // Add classes to the main module
    module.add_class::<Config>()?;
    module.add_class::<PyKeyfile>()?;
    module.add_class::<PyKeypair>()?;
    module.add_class::<Wallet>()?;

    // Add submodules to the main module
    register_config_module(module.clone())?;
    register_errors_module(module.clone())?;
    register_keyfile_module(module.clone())?;
    register_keypair_module(py, module.clone())?;
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
    errors_module.add(
        "WalletError",
        main_module.py().get_type_bound::<WalletError>(),
    )?;
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
        .map_err(|inner| PyErr::new::<PyKeyFileError, _>(PyKeyFileError { inner }))
}

#[pyfunction(name = "deserialize_keypair_from_keyfile_data")]
fn py_deserialize_keypair_from_keyfile_data(keyfile_data: &[u8]) -> PyResult<PyKeypair> {
    keyfile::deserialize_keypair_from_keyfile_data(keyfile_data)
        .map(|inner| PyKeypair { inner })
        .map_err(|inner| PyErr::new::<PyKeyFileError, _>(PyKeyFileError { inner }))
}

#[pyfunction(name = "validate_password")]
fn py_validate_password(password: &str) -> PyResult<bool> {
    keyfile::validate_password(password)
        .map_err(|inner| PyErr::new::<PyKeyFileError, _>(PyKeyFileError { inner }))
}

#[pyfunction(name = "ask_password")]
fn py_ask_password(validation_required: bool) -> PyResult<String> {
    keyfile::ask_password(validation_required)
        .map_err(|inner| PyErr::new::<PyKeyFileError, _>(PyKeyFileError { inner }))
}

#[pyfunction(name = "legacy_encrypt_keyfile_data")]
#[pyo3(signature = (keyfile_data, password=None))]
fn py_legacy_encrypt_keyfile_data(
    keyfile_data: &[u8],
    password: Option<String>,
) -> PyResult<Vec<u8>> {
    keyfile::legacy_encrypt_keyfile_data(keyfile_data, password)
        .map_err(|inner| PyErr::new::<PyKeyFileError, _>(PyKeyFileError { inner }))
}

#[pyfunction(name = "get_password_from_environment")]
fn py_get_password_from_environment(env_var_name: String) -> PyResult<Option<String>> {
    keyfile::get_password_from_environment(env_var_name)
        .map_err(|inner| PyErr::new::<PyKeyFileError, _>(PyKeyFileError { inner }))
}

#[pyfunction(name = "encrypt_keyfile_data")]
#[pyo3(signature = (keyfile_data, password=None))]
fn py_encrypt_keyfile_data(keyfile_data: &[u8], password: Option<String>) -> PyResult<Cow<[u8]>> {
    keyfile::encrypt_keyfile_data(keyfile_data, password)
        .map(Cow::from)
        .map_err(|inner| PyErr::new::<PyKeyFileError, _>(PyKeyFileError { inner }))
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
        .map_err(|inner| PyErr::new::<PyKeyFileError, _>(PyKeyFileError { inner }))
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

fn register_keypair_module(py: Python, main_module: Bound<'_, PyModule>) -> PyResult<()> {
    let keypair_module = PyModule::new_bound(py, "keypair")?;

    // Import the substrateinterface Keypair class
    let substrate_module = py.import_bound("substrateinterface")?;
    let origin_keypair_class = substrate_module.getattr("Keypair")?;

    // Downcast origin_keypair_class to &PyType
    let origin_keypair_class = origin_keypair_class.downcast::<PyType>()?;

    // Get pykeypair_type as &PyType
    let pykeypair_type = py.get_type_bound::<PyKeypair>();

    // Update base and mro in Wallet Keypair type
    unsafe {
        (*pykeypair_type.as_type_ptr()).tp_base = origin_keypair_class.as_ptr() as *mut _;

        let mro_tuple = PyTuple::new_bound(py, &[pykeypair_type.as_ref(), &origin_keypair_class]);
        ffi::Py_INCREF(mro_tuple.as_ptr());
        (*pykeypair_type.as_type_ptr()).tp_mro = mro_tuple.as_ptr() as *mut _;

        if ffi::PyType_Ready(pykeypair_type.as_type_ptr()) != 0 {
            return Err(PyErr::fetch(py));
        }
    }

    keypair_module.add("Keypair", pykeypair_type)?;
    main_module.add_submodule(&keypair_module)?;
    Ok(())
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
    utils_module.add_function(wrap_pyfunction!(is_valid_ss58_address, &utils_module)?)?;

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
        _py: Python,
    ) -> PyResult<Self> {
        // Handle config conversion
        let rust_config = match config {
            Some(_cfg) => {
                // Convert PyObject to RustConfig if necessary
                // TODO: Implement config conversion
                None
            }
            None => None,
        };

        let rust_wallet = RustWallet::new(name, hotkey, path, rust_config);
        Ok(Wallet { inner: rust_wallet })
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(self.inner.to_string())
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
            .map_err(|e| {
                PyErr::new::<PyException, _>(format!("Failed to create wallet: {:?}", e))
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
            .map_err(|e| {
                PyErr::new::<PyException, _>(format!("Failed to recreate wallet: {:?}", e))
            })?;

        Ok(Wallet { inner: result })
    }

    #[pyo3(signature = (password=None))]
    fn get_coldkey(&self, password: Option<String>) -> PyResult<PyKeypair> {
        let keypair = self
            .inner
            .get_coldkey(password)
            .map_err(|e| PyErr::new::<PyException, _>(format!("Failed to get coldkey: {:?}", e)))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[pyo3(signature = (password=None))]
    fn get_coldkeypub(&self, password: Option<String>) -> PyResult<PyKeypair> {
        let keypair = self.inner.get_coldkeypub(password).map_err(|e| {
            PyErr::new::<PyException, _>(format!("Failed to get coldkeypub: {:?}", e))
        })?;
        Ok(PyKeypair { inner: keypair })
    }

    #[pyo3(signature = (password=None))]
    fn get_hotkey(&self, password: Option<String>) -> PyResult<PyKeypair> {
        let keypair = self
            .inner
            .get_hotkey(password)
            .map_err(|e| PyErr::new::<PyException, _>(format!("Failed to get hotkey: {:?}", e)))?;
        Ok(PyKeypair { inner: keypair })
    }

    // Getters
    #[getter(coldkey)]
    fn coldkey_py_property(&self) -> PyResult<PyKeypair> {
        let keypair = self
            .inner
            .coldkey_property()
            .map_err(|e| PyErr::new::<PyException, _>(format!("Failed to get coldkey: {:?}", e)))?;
        Ok(PyKeypair { inner: keypair })
    }

    #[getter(coldkeypub)]
    fn coldkeypub_py_property(&self) -> PyResult<PyKeypair> {
        let keypair = self.inner.coldkeypub_property().map_err(|e| {
            PyErr::new::<PyException, _>(format!("Failed to get coldkeypub: {:?}", e))
        })?;
        Ok(PyKeypair { inner: keypair })
    }

    #[getter(hotkey)]
    fn hotkey_py_property(&self) -> PyResult<PyKeypair> {
        let keypair = self
            .inner
            .hotkey_property()
            .map_err(|e| PyErr::new::<PyException, _>(format!("Failed to get hotkey: {:?}", e)))?;
        Ok(PyKeypair { inner: keypair })
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
        signature = (uri, use_password=None, overwrite=None, suppress=None, save_coldkey_to_env=None, coldkey_password=None)
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
                PyErr::new::<PyException, _>(format!("Failed to create coldkey from uri: {:?}", e))
            })
    }

    #[pyo3(
        signature = (uri, use_password=None, overwrite=None, suppress=None, save_hotkey_to_env=None, hotkey_password=None)
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
                PyErr::new::<PyException, _>(format!("Failed to create hotkey from uri: {:?}", e))
            })
    }

    #[pyo3(text_signature = "($self)")]
    fn unlock_coldkey(&mut self) -> PyResult<PyKeypair> {
        self.inner
            .unlock_coldkey()
            .map(|inner| PyKeypair { inner })
            .map_err(|e| PyErr::new::<PyException, _>(format!("Failed to unlock coldkey: {:?}", e)))
    }

    #[pyo3(text_signature = "($self)")]
    fn unlock_coldkeypub(&mut self) -> PyResult<PyKeypair> {
        self.inner
            .unlock_coldkeypub()
            .map(|inner| PyKeypair { inner })
            .map_err(|e| {
                PyErr::new::<PyException, _>(format!("Failed to unlock coldkeypub: {:?}", e))
            })
    }

    #[pyo3(text_signature = "($self)")]
    fn unlock_hotkey(&mut self) -> PyResult<PyKeypair> {
        self.inner
            .unlock_hotkey()
            .map(|inner| PyKeypair { inner })
            .map_err(|e| PyErr::new::<PyException, _>(format!("Failed to unlock hotkey: {:?}", e)))
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
                PyErr::new::<PyException, _>(format!("Failed to create new coldkey: {:?}", e))
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
                PyErr::new::<PyException, _>(format!("Failed to create new hotkey: {:?}", e))
            })
    }

    #[pyo3(signature = (
        mnemonic=None,
        seed=None,
        json=None,
        use_password=None,
        overwrite=None,
        suppress=None,
        save_coldkey_to_env=None,
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
                use_password.unwrap_or(false),
                overwrite.unwrap_or(false),
                suppress.unwrap_or(false),
                save_coldkey_to_env.unwrap_or(false),
                coldkey_password,
            )
            .map_err(|e| {
                PyErr::new::<WalletError, _>(format!("Failed to regenerate coldkey: {:?}", e))
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
            .map_err(|e| {
                PyErr::new::<WalletError, _>(format!("Failed to regenerate coldkeypub: {:?}", e))
            })?;
        self.inner = new_inner_wallet;
        Ok(())
    }

    #[pyo3(signature = (
        mnemonic=None,
        seed=None,
        json=None,
        use_password=None,
        overwrite=None,
        suppress=None,
        save_hotkey_to_env=None,
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
                PyErr::new::<PyException, _>(format!("Failed to regenerate hotkey: {:?}", e))
            })?;
        self.inner = new_inner_wallet;
        Ok(())
    }
}
