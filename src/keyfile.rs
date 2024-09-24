use pyo3::prelude::*;
use crate::keypair::Keypair;

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
    pub fn keypair(&self) -> PyResult<Self> {
        Ok(self.get_keypair(None)?)
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

    /// Returns the keypair from the path, decrypts data if the file is encrypted.
    #[pyo3(signature = (password = None))]
    pub fn get_keypair(&self, password: Option<String>) -> PyResult<Self> {
        let path = "path";
        let name = "name";
        println!("{:?}", password);

        let kf = Keyfile {
            name: name.to_string(),
            path: path.to_string(),
        };

        Ok(kf)
    }

    /// Creates directories for the path if they do not exist.
    pub fn make_dir(&self) {
        // make a dir
    }

    /// Returns ``True`` if the file exists on the device.
    pub fn exists_on_device(&self) -> PyResult<bool> {
        Ok(true)
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
