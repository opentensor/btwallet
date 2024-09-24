use pyo3::prelude::*;
use pyo3::types::PyBytes;

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::keypair::Keypair;

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
        let metadata = fs::metadata(&self.path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to get metadata for file: {}.", e)))?;

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
        let metadata = fs::metadata(&self.path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to get metadata for file: {}", e)))?;

        // check the permissions
        let permissions = metadata.permissions();
        let writable = permissions.mode() & 0o222 != 0; // check if file is writable

        Ok(writable)
    }

    /// Returns ``True`` if the file under path is encrypted.
    pub fn is_encrypted(&self) -> PyResult<bool> {
        Ok(true)
    }

    /// Asks the user if it is okay to overwrite the file.
    pub fn _may_overwrite(&self) -> PyResult<bool> {

        print!("File {} already exists. Overwrite? (y/N) ", self.path);
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read input");

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
    /// Returns:
    ///     keyfile_data (bytes): The keyfile data stored under the path.
    ///
    /// Raises:
    ///     PyPermissionError: Raised if the file does not exist or is not readable.
    pub fn _read_keyfile_data_from_file(&self, py: Python) -> PyResult<PyObject> {
        // check file exist
        if !self.exists_on_device()? {
            return Err(pyo3::exceptions::PyFileNotFoundError::new_err(format!("Keyfile at: {} does not exist.", self.path)));
        }

        // check if file readable
        if !self.is_readable()? {
            return Err(pyo3::exceptions::PyPermissionError::new_err(format!("Keyfile at: {} is not readable.", self.path)));
        }

        // open and read the file
        let mut file = fs::File::open(&self.path)
            .map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("Failed to open file: {}.", e)))?;
        let mut data_vec = Vec::new();
        file.read_to_end(&mut data_vec)
            .map_err(|e| pyo3::exceptions::PyOSError::new_err(format!("Failed to read file: {}.", e)))?;

        let data_bytes = PyBytes::new_bound(py, &*data_vec).into_py(py);
        Ok(data_bytes)
    }

    /// Writes the keyfile data to the file.
    /// Args:
    ///     keyfile_data (bytes): The byte data to store under the path.
    ///     overwrite (bool, optional): If ``True``, overwrites the data without asking for permission from the user. Default is ``False``.
    ///
    /// Raises:
    ///     PyPermissionError: Raised if the file is not writable or the user responds No to the overwrite prompt.
    #[pyo3(signature = (keyfile_data, overwrite = false))]
    pub fn _write_keyfile_data_to_file(&self, keyfile_data: &[u8], overwrite: bool) -> PyResult<()> {
        // ask user for rewriting
        if self.exists_on_device()? && !overwrite {
            if !self._may_overwrite()? {
                return Err(pyo3::exceptions::PyUserWarning::new_err(format!("Keyfile at: {} is not writable", self.path)));
            }
        }

        let mut keyfile = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)  // cleanup if rewrite
            .open(&self.path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to open file: {}.", e)))?;

        // write data
        keyfile.write_all(keyfile_data)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to write to file: {}.", e)))?;

        // set permissions
        let mut permissions = fs::metadata(&self.path)?.permissions();
        permissions.set_mode(0o600); // just for owner
        fs::set_permissions(&self.path, permissions)
            .map_err(|e| pyo3::exceptions::PyPermissionError::new_err(format!("Failed to set permissions: {}.", e)))?;
        Ok(())
    }
}
