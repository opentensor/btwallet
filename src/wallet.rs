
use crate::config::Config;
use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use crate::keypair::Keypair;
use colored::Colorize;
use pyo3::prelude::*;
use crate::keyfile::Keyfile;


/// Display the mnemonic and a warning message to keep the mnemonic safe.
#[pyfunction]
#[pyo3(signature = (mnemonic, key_type))]
fn display_mnemonic_msg(mnemonic: String, key_type: &str) {
    println!("{}", "\nIMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.".red());

    println!(
        "\nThe mnemonic to the new {} is: {}",
        key_type.blue(),
        mnemonic.green()
    );
    println!(
        "\nYou can use the mnemonic to recreate the key with `{}` in case it gets lost.",
        "btcli".green()
    );
}

#[derive(Clone)]
#[pyclass]
pub struct Wallet {
    pub name: String,
    pub path: String,
    pub hotkey: String,
    pub config: Option<Config>,
    // pub hotkey_str: String
}

#[pymethods]
impl Wallet {
    #[new]
    #[pyo3(signature = (name = None, hotkey = None, path = None, config = None))]
    fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>, config: Option<Config>) -> PyResult<Self> {
        // TODO: add logic for the config processing
        Ok(Wallet {
            name: name.unwrap_or_else(|| BT_WALLET_NAME.to_string()),
            hotkey: hotkey.unwrap_or_else(|| BT_WALLET_HOTKEY.to_string()),
            path: path.unwrap_or_else(|| BT_WALLET_PATH.to_string()),
            config: config.or(None),
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "Wallet(name='{:}', path='{:}', hotkey='{:}')",
            self.name, self.path, self.hotkey
        ))
    }

    fn __str__(&self) -> PyResult<String> {
        self.__repr__()
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false))]
    pub fn create_if_non_existent(&self, coldkey_use_password: bool, hotkey_use_password: bool, py: Python) -> PyResult<Self> {
        self.create(coldkey_use_password, hotkey_use_password, py)
    }

    /// Checks for existing coldkeypub and hotkeys and creates them if non-existent.
    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false))]
    pub fn recreate(&mut self, coldkey_use_password: bool, hotkey_use_password: bool, py: Python) -> PyResult<Self> {

        self.create_new_coldkey(12, coldkey_use_password, false, false, py)?;
        self.create_new_hotkey(12, hotkey_use_password, false, false, py)?;

        Ok(self.clone())
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false))]
    pub fn create(&self, coldkey_use_password: bool, hotkey_use_password: bool, py: Python) -> PyResult<Self> {
        unimplemented!()
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words=12, use_password=true, overwrite=false, suppress=false))]
    fn create_new_coldkey(&mut self, n_words: usize, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Self> {

        let mnemonic = Keypair::generate_mnemonic(n_words)?;
        let keypair = Keypair::create_from_mnemonic(&mnemonic)?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "coldkey");
        }

        self.set_coldkey(keypair.clone(), use_password, overwrite, py)?;
        self.set_coldkeypub(keypair.clone(), use_password, overwrite, py)?;

        Ok(self.clone())
    }

    /// Property that returns the hotkey file.
    #[getter]
    pub fn hotkey_file(&self, py: Python) -> PyResult<Keyfile> {
        unimplemented!()
    }

    /// Property that returns the coldkey file.
    #[getter]
    pub fn coldkey_file(&self, py: Python) -> PyResult<Keyfile> {
        unimplemented!()
    }

    /// Property that returns the coldkeypub file.
    #[getter]
    pub fn coldkeypub_file(&self, py: Python) -> PyResult<Keyfile> {
        unimplemented!()
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words=12, use_password=false, overwrite=false, suppress=false))]
    pub fn create_new_hotkey(&mut self, n_words: usize, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Self> {

        let mnemonic = Keypair::generate_mnemonic(n_words)?;
        let keypair = Keypair::create_from_mnemonic(&mnemonic)?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "hotkey");
        }

        self.set_hotkey(keypair.clone(), use_password, overwrite, py)?;
        Ok(self.clone())
    }

    /// Sets the hotkey for the wallet.
    #[pyo3(signature = (keypair, encrypt=true, overwrite=false))]
    pub fn set_coldkey(&self, keypair: Keypair, encrypt: bool, overwrite: bool, py: Python) -> PyResult<Self> {
        unimplemented!()
    }

    /// Sets the coldkeypub for the wallet.
    #[pyo3(signature = (keypair, encrypt=false, overwrite=false))]
    pub fn set_coldkeypub(&self, keypair: Keypair, encrypt: bool, overwrite: bool, py: Python) -> PyResult<Self> {
        unimplemented!()
    }

    /// Sets the hotkey for the wallet.
    #[pyo3(signature = (keypair, encrypt=false, overwrite=false))]
    pub fn set_hotkey(&self, keypair: Keypair, encrypt: bool, overwrite: bool, py: Python) -> PyResult<Self> {
        unimplemented!()
    }

    /// Gets the coldkey from the wallet.
    #[pyo3(signature = (password))]
    pub fn get_coldkey(&self, password: Option<String>) -> PyResult<Keypair> {
        unimplemented!()
    }

    /// Gets the coldkeypub from the wallet.
    #[pyo3(signature = (password))]
    pub fn get_coldkeypub(&self, password: Option<String>) -> PyResult<Keypair> {
        unimplemented!()
    }

    /// Gets the hotkey from the wallet.
    #[pyo3(signature = (password))]
    pub fn get_hotkey(&self, password: Option<String>) -> PyResult<Keypair> {
        unimplemented!()
    }
}
