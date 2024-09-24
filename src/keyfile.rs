use pyo3::prelude::*;
use crate::keypair::Keypair;

use std::env;
use std::fs;
use std::path::Path;

const NACL_SALT: &[u8] = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1";

/// Serializes keypair object into keyfile data.
///
///     Args:
///         keypair (Keypair): The keypair object to be serialized.
///     Returns:
///         data (bytes): Serialized keypair data.
#[pyfunction]
pub fn serialized_keypair_to_keyfile_data(_py: Python, keypair: &Keypair) -> PyResult<Vec<u8>> {
    // TODO: implement this function
    unimplemented!();
}

/// Deserializes Keypair object from passed keyfile data.
///
///     Args:
///         keyfile_data (bytes): The keyfile data as bytes to be loaded.
///     Returns:
///         keypair (Keypair): The Keypair loaded from bytes.
///     Raises:
///         KeyFileError: Raised if the passed bytes cannot construct a keypair object.
#[pyfunction]
pub fn deserialize_keypair_from_keyfile_data(_py: Python, keyfile_data: Vec<u8>) -> PyResult<Keypair> {
    // TODO: implement this function
    unimplemented!();
}

/// Validates the password against a password policy.
///
///     Args:
///         password (str): The password to verify.
///     Returns:
///         valid (bool): ``True`` if the password meets validity requirements.
#[pyfunction]
pub fn validate_password(_py: Python, password: &str) -> PyResult<bool> {
    // TODO: implement this function
    unimplemented!();
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
pub fn keyfile_data_is_encrypted_nacl(_py: Python, keyfile_data: Vec<u8>) -> PyResult<bool> {
    // TODO: Implement the function
    unimplemented!();
}

/// Returns true if the keyfile data is ansible encrypted.
///
/// # Args
/// * `keyfile_data` - The bytes to validate.
///
/// # Returns
/// * `is_ansible` - True if the data is ansible encrypted.
#[pyfunction]
pub fn keyfile_data_is_encrypted_ansible(_py: Python, keyfile_data: Vec<u8>) -> PyResult<bool> {
    // TODO: Implement the function
    unimplemented!()
}

/// Returns true if the keyfile data is legacy encrypted.
///
/// # Args
/// * `keyfile_data` - The bytes to validate.
///
/// # Returns
/// * `is_legacy` - `true` if the data is legacy encrypted.
#[pyfunction]
pub fn keyfile_data_is_encrypted_legacy(_py: Python, keyfile_data: Vec<u8>) -> PyResult<bool> {
    // TODO: Implement the function
    unimplemented!()
}

/// Returns `true` if the keyfile data is encrypted.
///
/// # Args
/// * `keyfile_data` - The bytes to validate.
///
/// # Returns
/// * `is_encrypted` - `true` if the data is encrypted.
#[pyfunction]
pub fn keyfile_data_is_encrypted(_py: Python, keyfile_data: Vec<u8>) -> PyResult<bool> {
    // TODO: Implement the function
    unimplemented!()
}

/// Returns type of encryption method as a string.
///
/// # Args
///
/// * `keyfile_data` - Bytes to validate.
///
/// # Returns
///
/// * A string representing the name of encryption method.
#[pyfunction]
pub fn keyfile_data_encryption_method(_py: Python, keyfile_data: Vec<u8>) -> PyResult<String> {
    // TODO: Implement the function.
    unimplemented!()
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
#[pyfunction]
pub fn legacy_encrypt_keyfile_data(_py: Python, keyfile_data: Vec<u8>, password: Option<String>, ) -> PyResult<Vec<u8>> {
    // TODO: Implement the body of the function
    unimplemented!()
}

/// Encrypts the passed keyfile data using ansible vault.
///
/// # Args
/// * `keyfile_data` - The bytes to encrypt.
/// * `password` - The password used to encrypt the data. If `None`, asks for user input.
///
/// # Returns
/// * `encrypted_data` - The encrypted data.
#[pyfunction]
pub fn encrypt_keyfile_data(_py: Python, keyfile_data: Vec<u8>, password: Option<String>) -> PyResult<Vec<u8>> {
    // TODO: Implement the function
    unimplemented!()
}

/// Retrieves the cold key password from the environment variables.
///
/// # Args
/// * `coldkey_name` - The name of the cold key.
///
/// # Returns
/// * `Option<String>` - The password retrieved from the environment variables, or `None` if not found.
#[pyfunction]
pub fn get_coldkey_password_from_environment(_py: Python, coldkey_name: String) -> PyResult<Option<String>> {
    let password = env::var(coldkey_name).ok();
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
#[pyfunction]
pub fn decrypt_keyfile_data(_py: Python, keyfile_data: Vec<u8>, password: Option<String>, coldkey_name: Option<String>, ) -> PyResult<Vec<u8>> {
    // TODO: Implement the function
    unimplemented!()
}



#[pyclass]
pub struct Keyfile {
    path: String,
    name: String,
}

#[pymethods]
impl Keyfile {

    #[new]
    #[pyo3(signature = (path, name))]
    pub fn new (path: String, name: String) -> PyResult<Self> {
        Ok(
            Keyfile {
                path,
                name
            }
        )
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
    pub fn set_keypair(&self, keypair: Keypair, encrypt: bool, overwrite: bool, password: Option<String>)  {
        //set keypair
        println!("{:?} {:?} {:?} {:?}", keypair.ss58_address(), encrypt, overwrite, password);
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
    pub fn exists_on_device(&self) -> PyResult<bool> {
        let path: &Path = self.path.as_ref();
        match fs::metadata(path) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(_) => Ok(false),
        }
    }

    /// Returns ``True`` if the file under path is readable.
    pub fn is_readable(&self) -> PyResult<bool> {
        Ok(true)
    }

    /// Returns ``True`` if the file under path is writable.
    pub fn is_writable(&self) -> PyResult<bool> {
        Ok(true)
    }

    /// Returns ``True`` if the file under path is encrypted.
    pub fn is_encrypted(&self) -> PyResult<bool> {
        Ok(true)
    }

    /// Asks the user if it is okay to overwrite the file.
    fn _may_overwrite(&self) -> PyResult<bool> {
        Ok(true)
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
    fn _read_keyfile_data_from_file(&self) {
        // do something
    }

    /// Writes the keyfile data to the file.
    fn write_keyfile_data_to_file(&self) {
        // do something
    }
}
