// use pyo3::exceptions::{
//     PyFileNotFoundError, PyIOError, PyOSError, PyPermissionError, PyRuntimeError, PyUnicodeDecodeError, PyValueError
// };
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::from_utf8;

use ansible_vault::{decrypt_vault, encrypt_vault};
use fernet::Fernet;

use passwords::analyzer;
use passwords::scorer;
use serde_json::json;

use crate::errors::{KeyFileError, PasswordError};
use crate::keypair::Keypair;
use crate::utils;

use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretbox;

type PyFileNotFoundError = KeyFileError;
type PyIOError = KeyFileError;
type PyOSError = KeyFileError;
type PyPermissionError = KeyFileError;
type PyRuntimeError = KeyFileError;
type PyUnicodeDecodeError = KeyFileError;
type PyValueError = KeyFileError;

const NACL_SALT: &[u8] = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1";
const LEGACY_SALT: &[u8] = b"Iguesscyborgslikemyselfhaveatendencytobeparanoidaboutourorigins";

/// Serializes keypair object into keyfile data.
///
///     Args:
///         keypair (Keypair): The keypair object to be serialized.
///     Returns:
///         data (bytes): Serialized keypair data.
#[pyfunction]
#[pyo3(signature = (keypair))]
pub fn serialized_keypair_to_keyfile_data(py: Python, keypair: &Keypair) -> PyResult<PyObject> {
    let mut data: HashMap<&str, serde_json::Value> = HashMap::new();

    // publicKey and privateKey fields are optional. If they exist, hex prefix "0x" is added to them.
    if let Ok(Some(public_key)) = keypair.public_key(py) {
        let public_bytes: &PyBytes = public_key.extract(py)?;
        let public_key_str = hex::encode(public_bytes.as_bytes());
        data.insert("accountId", json!(format!("0x{}", public_key_str)));
        data.insert("publicKey", json!(format!("0x{}", public_key_str)));
    }
    if let Ok(Some(private_key)) = &keypair.private_key(py) {
        let private_bytes: &PyBytes = private_key.extract(py)?;
        let private_key_str = hex::encode(private_bytes.as_bytes());
        data.insert("privateKey", json!(format!("0x{}", private_key_str)));
    }

    // mnemonic and ss58_address fields are optional.
    if let Ok(Some(mnemonic)) = &keypair.mnemonic() {
        data.insert("secretPhrase", json!(mnemonic));
    }

    // the seed_hex field is optional. If it exists, hex prefix "0x" is added to it.
    if let Ok(Some(seed_hex_obj)) = keypair.seed_hex(py) {
        let seed_hex = seed_hex_obj
            .extract::<Vec<u8>>(py)
            .unwrap_or_else(|_| Vec::new());
        let seed_hex_str = match from_utf8(&seed_hex) {
            Ok(s) => s.to_string(),
            Err(_) => hex::encode(seed_hex),
        };
        data.insert("secretSeed", json!(format!("0x{}", seed_hex_str)));
    }

    if let Ok(Some(ss58_address)) = &keypair.ss58_address() {
        data.insert("ss58Address", json!(ss58_address));
    }

    // Serialize the data into JSON string and return it as bytes
    let json_data = serde_json::to_string(&data).map_err(|e| {
        PyErr::new::<PyUnicodeDecodeError, _>(format!("Serialization error: {}", e))
    })?;
    Ok(PyBytes::new_bound(py, &json_data.into_bytes()).into_py(py))
}

/// Deserializes Keypair object from passed keyfile data.
///
///     Args:
///         keyfile_data (PyBytes): The keyfile data to be loaded.
///     Returns:
///         keypair (Keypair): The Keypair loaded from bytes.
///     Raises:
///         KeyFileError: Raised if the passed PyBytes cannot construct a keypair object.
#[pyfunction]
#[pyo3(signature = (keyfile_data))]
pub fn deserialize_keypair_from_keyfile_data(
    keyfile_data: &[u8],
    py: Python<'_>,
) -> PyResult<Keypair> {
    // Decode the keyfile data from PyBytes to a string
    let decoded = from_utf8(keyfile_data)
        .map_err(|_| PyErr::new::<PyUnicodeDecodeError, _>("Failed to decode keyfile data."))?;

    // Parse the JSON string into a HashMap
    let keyfile_dict: HashMap<String, Option<String>> = serde_json::from_str(decoded)
        .map_err(|_| PyErr::new::<KeyFileError, _>("Failed to parse keyfile data."))?;

    // Extract data from the keyfile
    let secret_seed = keyfile_dict.get("secretSeed").and_then(|v| v.clone());
    let secret_phrase = keyfile_dict.get("secretPhrase").and_then(|v| v.clone());
    let private_key = keyfile_dict.get("privateKey").and_then(|v| v.clone());
    let ss58_address = keyfile_dict.get("ss58Address").and_then(|v| v.clone());

    // Create the `Keypair` based on the available data
    let keypair = if let Some(secret_phrase) = secret_phrase {
        Keypair::create_from_mnemonic(secret_phrase.as_str())
    } else if secret_seed.is_some() {
        let seed_string: &Bound<PyAny> = &PyString::new_bound(py, secret_seed.unwrap().as_str());
        Keypair::create_from_seed(&seed_string.clone())
    } else if let Some(private_key) = private_key {
        Keypair::create_from_private_key(private_key.as_str())
    } else if ss58_address.is_some() {
        Ok(Keypair::new(ss58_address, None, None, 42, None, 1)?)
    } else {
        return Err(PyErr::new::<PyOSError, _>(
            "Keypair could not be created from keyfile data.",
        ));
    };
    keypair
}

/// Validates the password against a password policy.
///
///     Args:
///         password (str): The password to verify.
///     Returns:
///         valid (bool): ``True`` if the password meets validity requirements.
#[pyfunction]
#[pyo3(signature = (password))]
pub fn validate_password(_py: Python, password: &str) -> PyResult<bool> {
    // Check for an empty password
    if password.is_empty() {
        return Ok(false);
    }

    // Define the password policy
    let min_length = 6;
    let min_score = 20.0; // Adjusted based on the scoring system described in the documentation

    // Analyze the password
    let analyzed = analyzer::analyze(password);
    let score = scorer::score(&analyzed);

    // Check conditions
    if password.len() >= min_length && score >= min_score {
        // Prompt user to retype the password
        let password_verification_response =
            utils::prompt_password("Retype your password: ".to_string())
                .expect("Failed to read the password.");

        // Remove potential newline or whitespace at the end
        let password_verification = password_verification_response.trim();

        if password == password_verification {
            Ok(true)
        } else {
            utils::print("Passwords do not match.\n".to_string());
            Ok(false)
        }
    } else {
        utils::print("Password not strong enough. Try increasing the length of the password or the password complexity.\n".to_string());
        Ok(false)
    }
}

/// Prompts the user to enter a password for key encryption.
///
///     Returns:
///         password (str): The valid password entered by the user.
#[pyfunction]
pub fn ask_password(py: Python, validation_required: bool) -> PyResult<String> {
    let mut valid = false;
    let password = utils::prompt_password("Enter your password: ".to_string());

    if validation_required {
        while !valid {
            if let Some(ref password) = password {
                valid = validate_password(py, &password)?;
            } else {
                valid = true
            }
        }
    }

    Ok(password.unwrap_or("".to_string()).trim().to_string())
}

/// Returns `true` if the keyfile data is NaCl encrypted.
///
/// # Arguments
///
/// * `keyfile_data` - Bytes to validate
///
/// # Returns
///
/// * `is_nacl` - `true` if the data is ansible encrypted.
#[pyfunction]
pub fn keyfile_data_is_encrypted_nacl(_py: Python, keyfile_data: &[u8]) -> PyResult<bool> {
    if keyfile_data.starts_with(b"$NACL") {
        return Ok(true);
    }
    Ok(false)
}

/// Returns true if the keyfile data is ansible encrypted.
///
/// # Args
/// * `keyfile_data` - The bytes to validate.
///
/// # Returns
/// * `is_ansible` - True if the data is ansible encrypted.
#[pyfunction]
pub fn keyfile_data_is_encrypted_ansible(_py: Python, keyfile_data: &[u8]) -> PyResult<bool> {
    if keyfile_data.starts_with(b"$ANSIBLE_VAULT") {
        return Ok(true);
    }
    Ok(false)
}

/// Returns true if the keyfile data is legacy encrypted.
///
/// # Args
/// * `keyfile_data` - The bytes to validate.
///
/// # Returns
/// * `is_legacy` - `true` if the data is legacy encrypted.
#[pyfunction]
pub fn keyfile_data_is_encrypted_legacy(_py: Python, keyfile_data: &[u8]) -> PyResult<bool> {
    if keyfile_data.starts_with(b"gAAAAA") {
        return Ok(true);
    }
    Ok(false)
}

/// Returns `true` if the keyfile data is encrypted.
///
///     Args:
///         keyfile_data (bytes): The bytes to validate.
///
///     Returns:
///         is_encrypted (bool): `true` if the data is encrypted.
#[pyfunction]
#[pyo3(signature = (keyfile_data))]
pub fn keyfile_data_is_encrypted(_py: Python, keyfile_data: &[u8]) -> PyResult<bool> {
    let nacl = keyfile_data_is_encrypted_nacl(_py, keyfile_data)?;
    let ansible = keyfile_data_is_encrypted_ansible(_py, keyfile_data)?;
    let legacy = keyfile_data_is_encrypted_legacy(_py, keyfile_data)?;
    Ok(nacl || ansible || legacy)
}

/// Returns type of encryption method as a string.
///
///     Arguments:
///         keyfile_data (bytes): Bytes to validate.
///
///     Returns:
///         (str): A string representing the name of encryption method.
#[pyfunction]
#[pyo3(signature = (keyfile_data))]
pub fn keyfile_data_encryption_method(py: Python, keyfile_data: &[u8]) -> PyResult<String> {
    let encryption_method = match true {
        _ if keyfile_data_is_encrypted_nacl(py, keyfile_data)? => "NaCl",
        _ if keyfile_data_is_encrypted_ansible(py, keyfile_data)? => "Ansible Vault",
        _ if keyfile_data_is_encrypted_legacy(py, keyfile_data)? => "legacy",
        _ => "unknown",
    };

    Ok(encryption_method.to_string())
}

/// legacy_encrypt_keyfile_data.
///
///     Arguments:
///         keyfile_data (bytes): Bytes of data from the keyfile.
///         password (str): Optional string that represents the password.
///
///     Returns:
///         encrypted_data (bytes): The encrypted keyfile data in bytes.
#[pyfunction]
#[pyo3(signature = (keyfile_data, password))]
pub fn legacy_encrypt_keyfile_data(
    py: Python,
    keyfile_data: &[u8],
    password: Option<String>,
) -> PyResult<PyObject> {
    let password = password.unwrap_or_else(||
        // function to get password from user
        ask_password(py, true).unwrap());

    utils::print(
        ":exclamation_mark: Encrypting key with legacy encryption method...\n".to_string(),
    );

    // Encrypting key with legacy encryption method
    let encrypted_data = encrypt_vault(keyfile_data, password.as_str())
        .map_err(|err| PyErr::new::<KeyFileError, _>(format!("{}", err)))?;

    Ok(PyBytes::new_bound(py, &encrypted_data.into_bytes()).into_py(py))
}

/// Retrieves the cold key password from the environment variables.
///
/// # Args
/// * `coldkey_name` - The name of the cold key.
///
/// # Returns
/// * `Option<String>` - The password retrieved from the environment variables, or `None` if not found.
#[pyfunction]
#[pyo3(signature = (env_var_name))]
pub fn get_password_from_environment(
    _py: Python,
    env_var_name: String,
) -> PyResult<Option<String>> {
    match env::var(&env_var_name) {
        Ok(encrypted_password) => {
            let decrypted_password = decrypt_password(encrypted_password, env_var_name);
            Ok(Some(decrypted_password))
        }
        Err(_) => Ok(None),
    }
}

// decrypt of keyfile_data with secretbox
fn derive_key(password: &[u8]) -> secretbox::Key {
    let nacl_salt = pwhash::argon2i13::Salt::from_slice(NACL_SALT).expect("Invalid NACL_SALT.");
    let mut key = secretbox::Key([0; secretbox::KEYBYTES]);
    pwhash::argon2i13::derive_key(
        &mut key.0,
        password,
        &nacl_salt,
        pwhash::argon2i13::OPSLIMIT_SENSITIVE,
        pwhash::argon2i13::MEMLIMIT_SENSITIVE,
    )
    .expect("Failed to derive key for NaCl decryption.");
    key
}

/// Encrypts the passed keyfile data using ansible vault.
///
///     Args
///         keyfile_data (bytes): The bytes to encrypt.
///         password (str): The password used to encrypt the data. If `None`, asks for user input.
///
///     Returns
///         encrypted_data (bytes): The encrypted data.
#[pyfunction]
#[pyo3(signature = (keyfile_data, password))]
pub fn encrypt_keyfile_data(
    py: Python,
    keyfile_data: &[u8],
    password: Option<String>,
) -> PyResult<PyObject> {
    // get password or ask user
    let password = match password {
        Some(pwd) => pwd,
        None => ask_password(py, true)?,
    };

    utils::print("Encrypting...\n".to_string());

    // crate the key with pwhash Argon2i
    let key = derive_key(password.as_bytes());

    // encrypt the data using SecretBox
    let nonce = secretbox::gen_nonce();
    let encrypted_data = secretbox::seal(keyfile_data, &nonce, &key);

    // concatenate with b"$NACL"
    let mut result = b"$NACL".to_vec();
    result.extend_from_slice(&nonce.0);
    result.extend_from_slice(&encrypted_data);

    // return result as bytes for python
    Ok(PyBytes::new_bound(py, &result).into())
}

/// Decrypts the passed keyfile data using ansible vault.
///
///     Args
///         keyfile_data (): The bytes to decrypt.
///         password (str): The password used to decrypt the data. If `None`, asks for user input.
///         coldkey_name (str): The name of the cold key. If provided, retrieves the password from environment variables.
///
///     Returns
///         decrypted_data (bytes): The decrypted data.
#[pyfunction]
#[pyo3(signature = (keyfile_data, password = None, password_env_var = None))]
pub fn decrypt_keyfile_data(
    py: Python,
    keyfile_data: &[u8],
    password: Option<String>,
    password_env_var: Option<String>,
) -> PyResult<PyObject> {
    // decrypt of keyfile_data with secretbox
    fn nacl_decrypt(keyfile_data: &[u8], key: &secretbox::Key) -> PyResult<Vec<u8>> {
        let data = &keyfile_data[5..]; // Remove the $NACL prefix
        let nonce = secretbox::Nonce::from_slice(&data[0..secretbox::NONCEBYTES])
            .ok_or(PyErr::new::<PyRuntimeError, _>("Invalid nonce."))?;
        let ciphertext = &data[secretbox::NONCEBYTES..];
        secretbox::open(ciphertext, &nonce, key)
            .map_err(|_| PyErr::new::<PasswordError, _>("Wrong password for nacl decryption."))
    }

    // decrypt of keyfile_data with legacy way
    fn legacy_decrypt(password: &str, keyfile_data: &[u8]) -> PyResult<Vec<u8>> {
        let kdf = pbkdf2::pbkdf2_hmac::<sha2::Sha256>;
        let mut key = vec![0; 32];
        kdf(password.as_bytes(), LEGACY_SALT, 10000000, &mut key);

        let fernet_key = Fernet::generate_key();
        let fernet = Fernet::new(&fernet_key).unwrap();
        let keyfile_data_str = from_utf8(keyfile_data)?;
        fernet
            .decrypt(keyfile_data_str)
            .map_err(|_| PyErr::new::<PasswordError, _>("Wrong password for legacy decryption."))
    }

    let mut password = password;

    // Retrieve password from environment variable if env_var_name is provided
    if let Some(env_var_name_) = password_env_var {
        if password.is_none() {
            password = get_password_from_environment(py, env_var_name_)?;
        }
    }

    // If password is still None, ask the user for input
    if password.is_none() {
        password = Some(ask_password(py, false)?);
    }

    let password = password.unwrap();

    utils::print("Decrypting...\n".to_string());

    // NaCl decryption
    if keyfile_data_is_encrypted_nacl(py, keyfile_data)? {
        let key = derive_key(password.as_bytes());
        let decrypted_data = nacl_decrypt(keyfile_data, &key)
            .map_err(|_| PyErr::new::<PasswordError, _>("Wrong password for decryption."))?;
        return Ok(PyBytes::new_bound(py, &decrypted_data).into_py(py));
    }

    // Ansible Vault decryption
    if keyfile_data_is_encrypted_ansible(py, keyfile_data)? {
        let decrypted_data = decrypt_vault(keyfile_data, password.as_str())
            .map_err(|_| PyErr::new::<PasswordError, _>("Wrong password for decryption."))?;
        return Ok(PyBytes::new_bound(py, &decrypted_data).into_py(py));
    }

    // Legacy decryption
    if keyfile_data_is_encrypted_legacy(py, keyfile_data)? {
        let decrypted_data = legacy_decrypt(&password, keyfile_data)
            .map_err(|_| PyErr::new::<PasswordError, _>("Wrong password for decryption."))?;
        return Ok(PyBytes::new_bound(py, &decrypted_data).into_py(py));
    }

    // If none of the methods work, raise error
    Err(PyErr::new::<KeyFileError, _>(
        "Invalid or unknown encryption method.",
    ))
}

fn confirm_prompt(question: &str) -> bool {
    let choice = utils::prompt(format!("{} (y/N): ", question)).expect("Failed to read input.");
    choice.trim().to_lowercase() == "y"
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home_dir) = dirs::home_dir() {
            return path.replacen('~', home_dir.to_str().unwrap(), 1);
        }
    }
    path.to_string()
}

// Encryption password
fn encrypt_password(key: String, value: String) -> String {
    let mut encrypted = String::new();
    for (i, c) in value.chars().enumerate() {
        let encrypted_char = (c as u8) ^ (key.chars().nth(i % key.len()).unwrap() as u8);
        encrypted.push(encrypted_char as char);
    }
    encrypted
}

// Decrypting password
fn decrypt_password(data: String, key: String) -> String {
    let mut decrypted = String::new();
    for (i, c) in data.chars().enumerate() {
        let decrypted_char = (c as u8) ^ (key.chars().nth(i % key.len()).unwrap() as u8);
        decrypted.push(decrypted_char as char);
    }
    decrypted
}

#[derive(Clone)]
#[pyclass(subclass)]
pub struct Keyfile {
    path: String,
    _path: PathBuf,
    name: String,
    should_save_to_env: bool,
}

#[pymethods]
impl Keyfile {
    #[new]
    #[pyo3(signature = (path, name=None, should_save_to_env=false))]
    pub fn new(path: String, name: Option<String>, should_save_to_env: bool) -> PyResult<Self> {
        let expanded_path: PathBuf = PathBuf::from(expand_tilde(&path));
        let name = name.unwrap_or_else(|| "Keyfile".to_string());
        Ok(Keyfile {
            path,
            _path: expanded_path,
            name,
            should_save_to_env,
        })
    }

    #[allow(clippy::bool_comparison)]
    fn __str__(&self, py: Python) -> PyResult<String> {
        if self.exists_on_device()? != true {
            Ok(format!("keyfile (empty, {})>", self.path))
        } else if self.is_encrypted(py)? {
            let encryption_method = self._read_keyfile_data_from_file(py)?;
            Ok(format!(
                "Keyfile ({:?} encrypted, {})>",
                encryption_method, self.path
            ))
        } else {
            Ok(format!("keyfile (decrypted, {})>", self.path))
        }
    }

    fn __repr__(&self, py: Python) -> PyResult<String> {
        self.__str__(py)
    }

    /// Returns the keypair from path, decrypts data if the file is encrypted.
    #[getter(keypair)]
    pub fn keypair_py(&self, py: Python) -> PyResult<Keypair> {
        self.get_keypair(None, py)
    }

    /// Returns the keypair from the path, decrypts data if the file is encrypted.
    #[pyo3(signature = (password = None))]
    pub fn get_keypair(&self, password: Option<String>, py: Python) -> PyResult<Keypair> {
        // read file
        let keyfile_data = self._read_keyfile_data_from_file(py)?;

        let keyfile_data_bytes: &[u8] = keyfile_data.extract(py)?;

        // check if encrypted
        let decrypted_keyfile_data = if keyfile_data_is_encrypted(py, keyfile_data_bytes)? {
            decrypt_keyfile_data(py, keyfile_data_bytes, password, Some(self.env_var_name()?))?
        } else {
            keyfile_data
        };

        // convert decrypted data to bytes
        let decrypted_bytes: &[u8] = decrypted_keyfile_data.extract(py)?;

        // deserialization data into the Keypair
        deserialize_keypair_from_keyfile_data(decrypted_bytes, py)
    }

    /// Loads the name from keyfile.name or raises an error.
    #[getter(name)]
    pub fn get_name(&self) -> PyResult<String> {
        Ok(self.name.clone())
    }

    /// Loads the name from keyfile.path or raises an error.
    #[getter(path)]
    pub fn get_path(&self) -> PyResult<String> {
        Ok(self.path.clone())
    }

    /// Returns the keyfile data under path.
    #[getter]
    pub fn data(&self, py: Python) -> PyResult<PyObject> {
        self._read_keyfile_data_from_file(py)
    }

    /// Returns the keyfile data under path.
    #[getter]
    pub fn keyfile_data(&self, py: Python) -> PyResult<PyObject> {
        self._read_keyfile_data_from_file(py)
    }

    /// Returns local environment variable key name based on Keyfile path.
    #[getter]
    fn env_var_name(&self) -> PyResult<String> {
        let path = &self
            .path
            .replace(std::path::MAIN_SEPARATOR, "_")
            .replace('.', "_");
        Ok(format!("BT_PW_{}", path.to_uppercase()))
    }

    /// Writes the keypair to the file and optionally encrypts data.
    #[pyo3(signature = (keypair, encrypt = true, overwrite = false, password = None))]
    pub fn set_keypair(
        &self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        password: Option<String>,
        py: Python,
    ) -> PyResult<()> {
        self.make_dirs()?;

        let keyfile_data = serialized_keypair_to_keyfile_data(py, &keypair)?;

        let final_keyfile_data = if encrypt {
            let encrypted_data =
                encrypt_keyfile_data(py, keyfile_data.extract(py)?, password.clone())?;

            // store password to local env
            if self.should_save_to_env {
                self.save_password_to_env(password.clone(), py)?;
            }

            encrypted_data.extract::<&[u8]>(py)?
        } else {
            keyfile_data.extract::<&[u8]>(py)?
        };

        self._write_keyfile_data_to_file(final_keyfile_data, overwrite)?;

        Ok(())
    }

    /// Creates directories for the path if they do not exist.
    pub fn make_dirs(&self) -> PyResult<()> {
        if let Some(directory) = self._path.parent() {
            // check if the dir is exit already
            if !directory.exists() {
                // create the dir if not
                fs::create_dir_all(directory)?;
            }
        }
        Ok(())
    }

    /// Returns ``True`` if the file exists on the device.
    ///
    /// Returns:
    ///     readable (bool): ``True`` if the file is readable.
    pub fn exists_on_device(&self) -> PyResult<bool> {
        Ok(self._path.exists())
    }

    /// Returns ``True`` if the file under path is readable.
    pub fn is_readable(&self) -> PyResult<bool> {
        // check file exist
        if !self.exists_on_device()? {
            return Ok(false);
        }

        // get file metadata
        let metadata = fs::metadata(&self._path).map_err(|e| {
            PyErr::new::<PyIOError, _>(format!("Failed to get metadata for file: {}.", e))
        })?;

        // check permissions
        let permissions = metadata.permissions();
        let readable = permissions.mode() & 0o444 != 0; // check readability

        Ok(readable)
    }

    /// Returns ``True`` if the file under path is writable.
    ///
    /// Returns:
    ///     writable (bool): ``True`` if the file is writable.
    pub fn is_writable(&self) -> PyResult<bool> {
        // check if file exist
        if !self.exists_on_device()? {
            return Ok(false);
        }

        // get file metadata
        let metadata = fs::metadata(&self._path).map_err(|e| {
            PyErr::new::<PyIOError, _>(format!("Failed to get metadata for file: {}", e))
        })?;

        // check the permissions
        let permissions = metadata.permissions();
        let writable = permissions.mode() & 0o222 != 0; // check if file is writable

        Ok(writable)
    }

    /// Returns ``True`` if the file under path is encrypted.
    ///
    ///     Returns:
    ///         encrypted (bool): ``True`` if the file is encrypted.
    pub fn is_encrypted(&self, py: Python) -> PyResult<bool> {
        // check if file exist
        if !self.exists_on_device()? {
            return Ok(false);
        }

        // check readable
        if !self.is_readable()? {
            return Ok(false);
        }

        // get the data from file
        let keyfile_data = self._read_keyfile_data_from_file(py)?;

        // check if encrypted
        let is_encrypted = keyfile_data_is_encrypted(py, keyfile_data.extract(py)?)?;

        Ok(is_encrypted)
    }

    /// Asks the user if it is okay to overwrite the file.
    pub fn _may_overwrite(&self) -> bool {
        let choice = utils::prompt(format!(
            "File {} already exists. Overwrite? (y/N) ",
            self.path
        ))
        .expect("Failed to read input.");

        choice.trim().to_lowercase() == "y"
    }

    /// Check the version of keyfile and update if needed.
    #[pyo3(signature = (print_result = true, no_prompt = false))]
    pub fn check_and_update_encryption(
        &self,
        print_result: bool,
        no_prompt: bool,
        py: Python,
    ) -> PyResult<bool> {
        if !self.exists_on_device()? {
            if print_result {
                utils::print(format!("Keyfile '{}' does not exist.\n", self.path));
            }
            return Ok(false);
        }

        if !self.is_readable()? {
            if print_result {
                utils::print(format!("Keyfile '{}' is not readable.\n", self.path));
            }
            return Ok(false);
        }

        if !self.is_writable()? {
            if print_result {
                utils::print(format!("Keyfile '{}' is not writable.\n", self.path));
            }
            return Ok(false);
        }

        let update_keyfile = false;
        if !no_prompt {
            // read keyfile
            let keyfile_data = self._read_keyfile_data_from_file(py)?;
            let keyfile_data_bytes: &[u8] = keyfile_data.extract(py)?;

            // check if file is decrypted
            if keyfile_data_is_encrypted(py, keyfile_data_bytes)?
                && !keyfile_data_is_encrypted_nacl(py, keyfile_data_bytes)?
            {
                utils::print("You may update the keyfile to improve security...\n".to_string());

                // ask user for the confirmation for updating
                if update_keyfile == confirm_prompt("Update keyfile?") {
                    let mut stored_mnemonic = false;

                    // check mnemonic if saved
                    while !stored_mnemonic {
                        utils::print(
                            "Please store your mnemonic in case an error occurs...\n".to_string(),
                        );
                        if confirm_prompt("Have you stored the mnemonic?") {
                            stored_mnemonic = true;
                        } else if !confirm_prompt("Retry and continue keyfile update?") {
                            return Ok(false);
                        }
                    }

                    // try decrypt data
                    let mut decrypted_keyfile_data: Option<Vec<u8>> = None;
                    let mut password: Option<String> = None;
                    while decrypted_keyfile_data.is_none() {
                        let pwd = ask_password(py, false)?;
                        password = Some(pwd.clone());

                        match decrypt_keyfile_data(
                            py,
                            keyfile_data_bytes,
                            Some(pwd),
                            Some(self.env_var_name()?),
                        ) {
                            Ok(decrypted_data) => {
                                let data: Vec<u8> = decrypted_data.extract(py)?;
                                decrypted_keyfile_data = Some(data);
                            }
                            Err(_) => {
                                if !confirm_prompt("Invalid password, retry?") {
                                    return Ok(false);
                                }
                            }
                        }
                    }

                    // encryption of updated data
                    if let Some(password) = password {
                        if let Some(decrypted_data) = decrypted_keyfile_data {
                            let encrypted_keyfile_data =
                                encrypt_keyfile_data(py, &decrypted_data, Some(password))?;
                            self._write_keyfile_data_to_file(
                                encrypted_keyfile_data.extract(py)?,
                                true,
                            )?;
                        }
                    }
                }
            }
        }

        if print_result || update_keyfile {
            // check and get result
            let keyfile_data = self._read_keyfile_data_from_file(py)?;
            let keyfile_data_bytes: &[u8] = keyfile_data.extract(py)?;

            return if !keyfile_data_is_encrypted(py, keyfile_data_bytes)? {
                if print_result {
                    utils::print("Keyfile is not encrypted.\n".to_string());
                }
                Ok(false)
            } else if keyfile_data_is_encrypted_nacl(py, keyfile_data_bytes)? {
                if print_result {
                    utils::print("Keyfile is updated.\n".to_string());
                }
                Ok(true)
            } else {
                if print_result {
                    utils::print("Keyfile is outdated, please update using 'btcli'.\n".to_string());
                }
                Ok(false)
            };
        }
        Ok(false)
    }

    /// Encrypts the file under the path.
    #[pyo3(signature = (password = None))]
    pub fn encrypt(&self, mut password: Option<String>, py: Python) -> PyResult<()> {
        // checkers
        if !self.exists_on_device()? {
            return Err(PyErr::new::<PyValueError, _>(format!(
                "Keyfile at: {} does not exist",
                self.path
            )));
        }

        if !self.is_readable()? {
            return Err(PyErr::new::<PyPermissionError, _>(format!(
                "Keyfile at: {} is not readable",
                self.path
            )));
        }

        if !self.is_writable()? {
            return Err(PyErr::new::<PyPermissionError, _>(format!(
                "Keyfile at: {} is not writable",
                self.path
            )));
        }

        // read the data
        let keyfile_data = self._read_keyfile_data_from_file(py)?;
        let keyfile_data_bytes: &[u8] = keyfile_data.extract(py)?;

        let final_data = if !keyfile_data_is_encrypted(py, keyfile_data_bytes)? {
            let as_keypair = deserialize_keypair_from_keyfile_data(keyfile_data_bytes, py)?;
            let serialized_data = serialized_keypair_to_keyfile_data(py, &as_keypair)?;

            // get password from local env if exist
            if password.is_none() {
                password = get_password_from_environment(py, self.env_var_name()?)?;
            }

            let encrypted_keyfile_data =
                encrypt_keyfile_data(py, serialized_data.extract(py)?, password.clone())?;

            if self.should_save_to_env {
                self.save_password_to_env(password.clone(), py)?;
            }

            encrypted_keyfile_data
        } else {
            keyfile_data
        };

        // write back
        self._write_keyfile_data_to_file(final_data.extract(py)?, true)?;

        Ok(())
    }

    /// Decrypts the file under the path.
    #[pyo3(signature = (password = None))]
    pub fn decrypt(&self, password: Option<String>, py: Python) -> PyResult<()> {
        // checkers
        if !self.exists_on_device()? {
            return Err(PyErr::new::<PyOSError, _>(format!(
                "Keyfile at: {} does not exist.",
                self.path
            )));
        }
        if !self.is_readable()? {
            return Err(PyErr::new::<PyOSError, _>(format!(
                "Keyfile at: {} is not readable.",
                self.path
            )));
        }
        if !self.is_writable()? {
            return Err(PyErr::new::<PyOSError, _>(format!(
                "Keyfile at: {} is not writable.",
                self.path
            )));
        }

        // read data
        let keyfile_data = self._read_keyfile_data_from_file(py)?;
        let keyfile_data_bytes: &[u8] = keyfile_data.extract(py)?;

        let decrypted_data = if keyfile_data_is_encrypted(py, keyfile_data_bytes)? {
            decrypt_keyfile_data(py, keyfile_data_bytes, password, Some(self.env_var_name()?))?
        } else {
            keyfile_data
        };

        let decrypted_bytes: &[u8] = decrypted_data.extract(py)?;
        let as_keypair = deserialize_keypair_from_keyfile_data(decrypted_bytes, py)?;

        let serialized_data = serialized_keypair_to_keyfile_data(py, &as_keypair)?;
        self._write_keyfile_data_to_file(serialized_data.extract(py)?, true)?;
        Ok(())
    }

    /// Reads the keyfile data from the file.
    ///
    ///     Returns:
    ///         keyfile_data (bytes): The keyfile data stored under the path.
    ///
    ///     Raises:
    ///         PyPermissionError: Raised if the file does not exist or is not readable.
    pub fn _read_keyfile_data_from_file(&self, py: Python) -> PyResult<PyObject> {
        // check file exist
        if !self.exists_on_device()? {
            return Err(PyErr::new::<PyFileNotFoundError, _>(format!(
                "Keyfile at: {} does not exist.",
                self.path
            )));
        }

        // check if file readable
        if !self.is_readable()? {
            return Err(PyErr::new::<PyPermissionError, _>(format!(
                "Keyfile at: {} is not readable.",
                self.path
            )));
        }

        // open and read the file
        let mut file = fs::File::open(&self._path)
            .map_err(|e| PyErr::new::<PyOSError, _>(format!("Failed to open file: {}.", e)))?;
        let mut data_vec = Vec::new();
        file.read_to_end(&mut data_vec)
            .map_err(|e| PyErr::new::<PyOSError, _>(format!("Failed to read file: {}.", e)))?;

        let data_bytes = PyBytes::new_bound(py, &data_vec).into_py(py);
        Ok(data_bytes)
    }

    /// Writes the keyfile data to the file.
    ///
    ///     Arguments:
    ///         keyfile_data (bytes): The byte data to store under the path.
    ///         overwrite (bool, optional): If ``True``, overwrites the data without asking for permission from the user. Default is ``False``.
    ///
    ///     Raises:
    ///         PyPermissionError: Raised if the file is not writable or the user responds No to the overwrite prompt.
    #[pyo3(signature = (keyfile_data, overwrite = false))]
    pub fn _write_keyfile_data_to_file(
        &self,
        keyfile_data: &[u8],
        overwrite: bool,
    ) -> PyResult<()> {
        // ask user for rewriting
        if self.exists_on_device()? && !overwrite && !self._may_overwrite() {
            return Err(PyErr::new::<KeyFileError, _>(format!(
                "Keyfile at: {} is not writable",
                self.path
            )));
        }

        let mut keyfile = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true) // cleanup if rewrite
            .open(&self._path)
            .map_err(|e| PyErr::new::<PyIOError, _>(format!("Failed to open file: {}.", e)))?;

        // write data
        keyfile
            .write_all(keyfile_data)
            .map_err(|e| PyErr::new::<PyIOError, _>(format!("Failed to write to file: {}.", e)))?;

        // set permissions
        let mut permissions = fs::metadata(&self._path)?.permissions();
        permissions.set_mode(0o600); // just for owner
        fs::set_permissions(&self._path, permissions).map_err(|e| {
            PyErr::new::<PyPermissionError, _>(format!("Failed to set permissions: {}.", e))
        })?;
        Ok(())
    }

    /// Saves the key's password to the associated local environment variable.
    #[pyo3(signature = (password=None))]
    fn save_password_to_env(&self, password: Option<String>, py: Python) -> PyResult<String> {
        // checking the password
        let password = match password {
            Some(pwd) => pwd,
            None => match ask_password(py, true) {
                Ok(pwd) => pwd,
                Err(e) => {
                    utils::print(format!("Error asking password: {:?}.\n", e));
                    return Ok("".parse()?);
                }
            },
        };
        // saving password
        match self.env_var_name() {
            Ok(env_var_name) => {
                // encrypt password
                let encrypted_password = encrypt_password(self.env_var_name()?, password);
                // store encrypted password
                env::set_var(&env_var_name, &encrypted_password);

                let message = format!(
                    "The password has been saved to environment variable '{}'.\n",
                    env_var_name
                );
                utils::print(message);
                Ok(encrypted_password)
            }
            Err(e) => {
                utils::print(format!(
                    "Error saving environment variable name: {:?}.\n",
                    e
                ));
                Ok("".parse()?)
            }
        }
    }

    /// Removes the password associated with the Keyfile from the local environment.
    fn remove_password_from_env(&self) -> PyResult<bool> {
        let env_var_name = self.env_var_name()?;

        if env::var(&env_var_name).is_ok() {
            env::remove_var(&env_var_name);
            let message = format!("Environment variable '{}' removed.\n", env_var_name);
            utils::print(message);
            Ok(true)
        } else {
            let message = format!("Environment variable '{}' does not exist.\n", env_var_name);
            utils::print(message);
            Ok(false)
        }
    }
}
