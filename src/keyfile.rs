use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write, stdin, stdout};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::str::from_utf8;

use passwords::analyzer;
use passwords::scorer;
use serde_json::json;

use crate::keypair::Keypair;

use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::pwhash::scryptsalsa208sha256::{Salt};

const NACL_SALT: &[u8] = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1";

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
        let public_key_str = hex::encode(public_bytes.as_bytes().to_vec());
        data.insert("accountId", json!(format!("0x{}", public_key_str)));
        data.insert("publicKey", json!(format!("0x{}", public_key_str)));
    }
    if let Ok(Some(private_key)) = &keypair.private_key(py) {
        let private_bytes: &PyBytes = private_key.extract(py)?;
        let private_key_str = hex::encode(private_bytes.as_bytes().to_vec());
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

    // TODO: consider to use pyo3::exceptions::Py* errors instead of `PyException`
    // Serialize the data into JSON string and return it as bytes
    let json_data = serde_json::to_string(&data).map_err(|e| {
        pyo3::exceptions::PyUnicodeDecodeError::new_err(format!("Serialization error: {}", e))
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
    _py: Python,
    keyfile_data: &[u8],
) -> PyResult<Keypair> {
    // TODO: consider to use pyo3::exceptions::Py* errors instead of `PyException`
    // Decode the keyfile data from PyBytes to a string
    let decoded = from_utf8(keyfile_data)
        .map_err(|_| PyException::new_err("Failed to decode keyfile data."))?;

    // TODO: consider to use pyo3::exceptions::Py* errors instead of `PyException`
    // Parse the JSON string into a HashMap
    let keyfile_dict: HashMap<String, Option<String>> = serde_json::from_str(decoded)
        .map_err(|_| PyException::new_err("Failed to parse keyfile data."))?;

    // Extract data from the keyfile
    let secret_seed = keyfile_dict.get("secretSeed").and_then(|v| v.clone());
    let secret_phrase = keyfile_dict.get("secretPhrase").and_then(|v| v.clone());
    let private_key = keyfile_dict.get("privateKey").and_then(|v| v.clone());
    let ss58_address = keyfile_dict.get("ss58Address").and_then(|v| v.clone());

    // Create the `Keypair` based on the available data
    let keypair = if secret_phrase.is_some() {
        Keypair::create_from_mnemonic(secret_phrase.unwrap().as_str())
    } else if secret_seed.is_some() {
        Keypair::create_from_seed(secret_seed.unwrap().as_str())
    } else if private_key.is_some() {
        Keypair::create_from_private_key(private_key.unwrap().as_str())
    } else if ss58_address.is_some() {
        Ok(Keypair::new(ss58_address, None, None, 42, None, 1)?)
    } else {
        // TODO: consider to use pyo3::exceptions::Py* errors instead of `PyException`
        return Err(PyException::new_err(
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
        let mut password_verification = String::new();

        print!("Retype your password: ");
        stdin()
            .read_line(&mut password_verification)
            .expect("Failed to read the password.");

        // Remove potential newline or whitespace at the end
        let password_verification = password_verification.trim();

        if password == password_verification {
            Ok(true)
        } else {
            println!("Passwords do not match.");
            Ok(false)
        }
    } else {
        println!("Password not strong enough. Try increasing the length of the password or the password complexity.");
        Ok(false)
    }
}

/// Prompts the user to enter a password for key encryption.
///
///     Returns:
///         password (str): The valid password entered by the user.
#[pyfunction]
pub fn ask_password_to_encrypt() -> PyResult<String> {
    let mut password = String::new();
    print!("Specify password for key encryption: ");
    stdout().flush()?;
    stdin().read_line(&mut password).expect("Filed to read the password.");
    Ok(password.trim().to_string())
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
/// # Args
///
/// * `keyfile_data` - Bytes of data from the keyfile.
///
/// * `password` - Optional string that represents the password.
///
/// # Returns
///
/// * `encrypted_data` - The encrypted keyfile data in bytes.
// #[pyfunction]
// pub fn legacy_encrypt_keyfile_data(_py: Python, keyfile_data: &[u8], password: Option<String>, ) -> PyResult<Vec<u8>> {
//     // TODO: Implement the body of the function
//     unimplemented!()
// }

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
pub fn encrypt_keyfile_data(py: Python, keyfile_data: &[u8], password: Option<String>) -> PyResult<PyObject> {
    // get password or ask user
    let password = match password {
        Some(pwd) => pwd,
        None => ask_password_to_encrypt()?,
    };
    let password_bytes = password.as_bytes();

    // add encryption parameters pwhash Argon2i
    let opslimit = pwhash::OPSLIMIT_SENSITIVE;
    let memlimit = pwhash::MEMLIMIT_SENSITIVE;

    // crate the key with pwhash Argon2i
    let mut key = secretbox::Key([0u8; secretbox::KEYBYTES]);
    let nacl_salt = &Salt::from_slice(NACL_SALT)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Invalid NACL_SALT."))?;
    pwhash::derive_key(&mut key.0, password_bytes, nacl_salt, opslimit, memlimit)
        .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("Failed to derive encryption key."))?;

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

/// Retrieves the cold key password from the environment variables.
///
/// # Args
/// * `coldkey_name` - The name of the cold key.
///
/// # Returns
/// * `Option<String>` - The password retrieved from the environment variables, or `None` if not found.
#[pyfunction]
#[pyo3(signature = (coldkey_name))]
pub fn get_coldkey_password_from_environment(_py: Python, coldkey_name: String, ) -> PyResult<Option<String>> {
    let env_key: String = String::from("BT_COLD_PW_");
    let coldkey_name = coldkey_name.to_uppercase().replace("-", "_");
    let coldkey_var_name = format!("{}{}", env_key, coldkey_name);
    let password = env::var(coldkey_var_name.clone()).ok();
    Ok(password)
}

/// Decrypts the passed keyfile data using ansible vault.
///
/// # Args
/// * `keyfile_data` - The bytes to decrypt.
/// * `password` - The password used to decrypt the data. If `None`, asks for user input.
/// * `coldkey_name` - The name of the cold key. If provided, retrieves the password from environment variables.
///
/// # Returns
/// * `decrypted_data` - The decrypted data.
// #[pyfunction]
// pub fn decrypt_keyfile_data(_py: Python, keyfile_data: &[u8], password: Option<String>, coldkey_name: Option<String>, ) -> PyResult<PyObject> {
//     // TODO: Implement the function
//     unimplemented!()
// }

#[pyclass]
pub struct Keyfile {
    path: String,
    name: String,
}

#[pymethods]
impl Keyfile {
    #[new]
    #[pyo3(signature = (path, name))]
    pub fn new(path: String, name: String) -> PyResult<Self> {
        Ok(Keyfile { path, name })
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("Keyfile ({} encrypted, {})>", self.path, self.name))
    }

    fn __repr__(&self) -> PyResult<String> {
        self.__str__()
    }

    /// Returns the keypair from path, decrypts data if the file is encrypted.
    #[getter]
    pub fn keypair(&self) -> PyResult<bool> {
        Ok(true)
    }

    /// Returns the keyfile data under path.
    #[getter]
    pub fn data(&self) -> PyResult<bool> {
        Ok(true)
    }

    /// Returns the keyfile data under path.
    #[getter]
    pub fn keyfile_data(&self) -> PyResult<bool> {
        Ok(true)
    }

    /// Writes the keypair to the file and optionally encrypts data.
    #[pyo3(signature = (keypair, encrypt = true, overwrite = false, password = None))]
    pub fn set_keypair(
        &self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        password: Option<String>,
    ) {
        //set keypair
        println!(
            "{:?} {:?} {:?} {:?}",
            keypair.ss58_address(),
            encrypt,
            overwrite,
            password
        );
    }

    // TODO (devs): rust creates the same function automatically by `keypair` getter function and the error accuses. We need to understand how to avoid this.
    // /// Returns the keypair from the path, decrypts data if the file is encrypted.
    // #[pyo3(signature = (password = None))]
    // pub fn get_keypair(&self, password: Option<String>) -> PyResult<bool> {
    //     println!("{:?}", password);
    //     Ok(true)
    // }

    /// Creates directories for the path if they do not exist.
    pub fn make_dirs(&self) -> PyResult<()> {
        // convert String to Path
        let path: &Path = self.path.as_ref();
        if let Some(directory) = path.parent() {
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
        Ok(Path::new(&self.path).exists())
    }

    /// Returns ``True`` if the file under path is readable.
    pub fn is_readable(&self) -> PyResult<bool> {
        // check file exist
        if !self.exists_on_device()? {
            return Ok(false);
        }

        // get file metadata
        let metadata = fs::metadata(&self.path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!("Failed to get metadata for file: {}.", e))
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
        let metadata = fs::metadata(&self.path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!("Failed to get metadata for file: {}", e))
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
    // pub fn is_encrypted(&self, py: Python) -> PyResult<bool> {
    //     // check if file exist
    //     if !self.exists_on_device()? {
    //         return Ok(false);
    //     }
    //
    //     // check readable
    //     if !self.is_readable()? {
    //         return Ok(false);
    //     }
    //
    //     // get the data from file
    //     let keyfile_data = self._read_keyfile_data_from_file(py)?;
    //
    //     // check if encrypted
    //     // let is_encrypted = keyfile_data_is_encrypted(py, keyfile_data)?;
    //
    //     Ok(is_encrypted)
    // }

    /// Asks the user if it is okay to overwrite the file.
    pub fn _may_overwrite(&self) -> PyResult<bool> {
        print!("File {} already exists. Overwrite? (y/N) ", self.path);
        stdout().flush()?;

        let mut choice = String::new();
        stdin()
            .read_line(&mut choice)
            .expect("Failed to read input.");

        Ok(choice.trim().to_lowercase() == "y")
    }

    /// Check the version of keyfile and update if needed.
    #[pyo3(signature = (print_result = true, no_prompt = false))]
    pub fn check_and_update_encryption(&self, print_result: bool, no_prompt: bool) {
        // do something
        println!("{:?} {:?}", print_result, no_prompt);
    }

    /// Encrypts the file under the path.
    #[pyo3(signature = (password = None))]
    pub fn encrypt(&self, password: Option<String>) {
        // do something
        println!("{:?}", password);
    }

    /// Decrypts the file under the path.
    #[pyo3(signature = (password = None))]
    pub fn decrypt(&self, password: Option<String>) {
        // do something
        println!("{:?}", password);
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
            return Err(pyo3::exceptions::PyFileNotFoundError::new_err(format!(
                "Keyfile at: {} does not exist.",
                self.path
            )));
        }

        // check if file readable
        if !self.is_readable()? {
            return Err(pyo3::exceptions::PyPermissionError::new_err(format!(
                "Keyfile at: {} is not readable.",
                self.path
            )));
        }

        // open and read the file
        let mut file = fs::File::open(&self.path).map_err(|e| {
            pyo3::exceptions::PyOSError::new_err(format!("Failed to open file: {}.", e))
        })?;
        let mut data_vec = Vec::new();
        file.read_to_end(&mut data_vec).map_err(|e| {
            pyo3::exceptions::PyOSError::new_err(format!("Failed to read file: {}.", e))
        })?;

        let data_bytes = PyBytes::new_bound(py, &*data_vec).into_py(py);
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
        if self.exists_on_device()? && !overwrite {
            if !self._may_overwrite()? {
                return Err(pyo3::exceptions::PyUserWarning::new_err(format!(
                    "Keyfile at: {} is not writable",
                    self.path
                )));
            }
        }

        let mut keyfile = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true) // cleanup if rewrite
            .open(&self.path)
            .map_err(|e| {
                pyo3::exceptions::PyIOError::new_err(format!("Failed to open file: {}.", e))
            })?;

        // write data
        keyfile.write_all(keyfile_data).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!("Failed to write to file: {}.", e))
        })?;

        // set permissions
        let mut permissions = fs::metadata(&self.path)?.permissions();
        permissions.set_mode(0o600); // just for owner
        fs::set_permissions(&self.path, permissions).map_err(|e| {
            pyo3::exceptions::PyPermissionError::new_err(format!(
                "Failed to set permissions: {}.",
                e
            ))
        })?;
        Ok(())
    }
}
