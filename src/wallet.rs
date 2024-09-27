use pyo3::prelude::*;
use pyo3::types::{PyString, PyType};

use std::ops::Deref;

use colored::Colorize;

use crate::config::Config;
use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use crate::keypair::Keypair;
use crate::keyfile::Keyfile;
use crate::utils::{is_valid_bittensor_address_or_public_key};

use dirs::home_dir;


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

    _coldkey: Option<Keypair>,
    _coldkeypub: Option<Keypair>,
    _hotkey: Option<Keypair>,
}

#[pymethods]
impl Wallet {
    #[new]
    #[pyo3(signature = (name = None, hotkey = None, path = None, config = None))]
    fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>, config: Option<Config>) -> PyResult<Wallet> {
        let final_name = name.or_else(|| Some(config.clone()?.wallet.name.clone())).unwrap_or_else(|| BT_WALLET_NAME.to_string());
        let final_hotkey = hotkey.or_else(|| Some(config.clone()?.wallet.hotkey.clone())).unwrap_or_else(|| BT_WALLET_HOTKEY.to_string());
        let final_path = path.or_else(|| Some(config.clone()?.wallet.path.clone())).unwrap_or_else(|| BT_WALLET_PATH.to_string());

        Ok(Wallet {
            name: final_name,
            hotkey: final_hotkey,
            path: final_path,
            config: config.or(None),
            _coldkey: None,
            _coldkeypub: None,
            _hotkey: None,
        })
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!(
            "Wallet (Name: '{:}', Hotkey: '{:}', Path: '{:}')",
            self.name, self.hotkey, self.path
        ))
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "name: '{:}', hotkey: '{:}', path: '{:}'",
            self.name, self.hotkey, self.path
        ))
    }

    /// Get config from the argument parser.
    #[classmethod]
    pub fn config(cls: &PyType) -> PyResult<Config> {
        Config::new(None, None, None)
    }

    /// Print help to stdout.
    #[classmethod]
    pub fn help(cls: &PyType) -> PyResult<Config> {
        unimplemented!()
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false))]
    pub fn create_if_non_existent(&self, coldkey_use_password: bool, hotkey_use_password: bool, py: Python) -> PyResult<Wallet> {
        self.create(coldkey_use_password, hotkey_use_password, py)
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false))]
    pub fn create(&self, coldkey_use_password: bool, hotkey_use_password: bool, py: Python) -> PyResult<Wallet> {
        unimplemented!()
    }

    /// Checks for existing coldkeypub and hotkeys and creates them if non-existent.
    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false))]
    pub fn recreate(&mut self, coldkey_use_password: bool, hotkey_use_password: bool, py: Python) -> PyResult<Wallet> {
        self.create_new_coldkey(12, coldkey_use_password, false, false, py)?;
        self.create_new_hotkey(12, hotkey_use_password, false, false, py)?;

        Ok(self.clone())
    }

    /// Property that returns the hotkey file.
    #[getter]
    pub fn hotkey_file(&self) -> PyResult<Keyfile> {
        // get home dir
        let home = home_dir().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("Failed to get user home directory.")
        })?;

        // concatenate wallet path
        let wallet_path = home.join(&self.path).join(&self.name);

        // concatenate hotkey path
        let hotkey_path = wallet_path.join("hotkeys").join(&self.hotkey);

        Keyfile::new(hotkey_path.to_string_lossy().into_owned(), self.name.clone())
    }

    /// Property that returns the coldkey file.
    #[getter]
    pub fn coldkey_file(&self) -> PyResult<Keyfile> {
        // get home dir
        let home = home_dir().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("Failed to get user home directory.")
        })?;

        // concatenate wallet path
        let wallet_path = home.join(&self.path).join(&self.name);

        // concatenate hotkey path
        let coldkey_path = wallet_path.join("coldkey");

        Keyfile::new(coldkey_path.to_string_lossy().into_owned(), self.name.clone())
    }

    /// Property that returns the coldkeypub file.
    #[getter]
    pub fn coldkeypub_file(&self) -> PyResult<Keyfile> {
        // get home dir
        let home = home_dir().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("Failed to get user home directory.")
        })?;

        // concatenate wallet path
        let wallet_path = home.join(&self.path).join(&self.name);

        // concatenate hotkey path
        let coldkeypub_path = wallet_path.join("coldkeypub.txt");

        Keyfile::new(coldkeypub_path.to_string_lossy().into_owned(), self.name.clone())
    }

    // TODO: the same problem as in keyfile.rs with the same name items withing one struct.
    // /// Loads the coldkey from wallet.path/wallet.name/coldkey or raises an error.
    // #[getter]
    // pub fn coldkey(&self, py: Python) -> PyResult<Keyfile> {
    //     unimplemented!()
    // }
    //
    // /// Loads the coldkeypub from wallet.path/wallet.name/coldkeypub.txt or raises an error.
    // #[getter]
    // pub fn coldkeypub(&self, py: Python) -> PyResult<Keyfile> {
    //     unimplemented!()
    // }
    //
    // /// Loads the hotkey from wallet.path/wallet.name/hotkeys/wallet.hotkey or raises an error.
    // #[getter]
    // pub fn hotkey(&self, py: Python) -> PyResult<Keyfile> {
    //     unimplemented!()
    // }

    /// Sets the hotkey for the wallet.
    #[pyo3(signature = (keypair, encrypt=true, overwrite=false))]
    pub fn set_coldkey(&mut self, keypair: Keypair, encrypt: bool, overwrite: bool, py: Python) -> PyResult<()> {
        self._coldkey = Some(keypair.clone());
        self.coldkey_file()?.set_keypair(keypair, encrypt, overwrite, None, py)
    }

    /// Sets the coldkeypub for the wallet.
    #[pyo3(signature = (keypair, encrypt=false, overwrite=false))]
    pub fn set_coldkeypub(&mut self, keypair: Keypair, encrypt: bool, overwrite: bool, py: Python) -> PyResult<()> {

        let _ss58_address = keypair.ss58_address()?.unwrap();
        let _coldkeypub_keypair = Keypair::new(Some(_ss58_address), None, None, 42, None, 1)?;

        self._coldkeypub = Some(_coldkeypub_keypair.clone());
        self.coldkeypub_file()?.set_keypair(_coldkeypub_keypair.clone(), encrypt, overwrite, None, py)
    }

    /// Sets the hotkey for the wallet.
    #[pyo3(signature = (keypair, encrypt=false, overwrite=false))]
    pub fn set_hotkey(&mut self, keypair: Keypair, encrypt: bool, overwrite: bool, py: Python) -> PyResult<()> {
        self._hotkey = Some(keypair.clone());
        self.hotkey_file()?.set_keypair(keypair.clone(), encrypt, overwrite, None, py)
    }

    /// Gets the coldkey from the wallet.
    #[pyo3(signature = (password = None))]
    pub fn get_coldkey(&self, password: Option<String>, py: Python) -> PyResult<Keypair> {
        self.coldkey_file()?.get_keypair(password, py)
    }

    /// Gets the coldkeypub from the wallet.
    #[pyo3(signature = (password = None))]
    pub fn get_coldkeypub(&self, password: Option<String>, py: Python) -> PyResult<Keypair> {
        self.coldkeypub_file()?.get_keypair(password, py)
    }

    /// Gets the hotkey from the wallet.
    #[pyo3(signature = (password = None))]
    pub fn get_hotkey(&self, password: Option<String>, py: Python) -> PyResult<Keypair> {
        self.hotkey_file()?.get_keypair(password, py)
    }

    /// Creates coldkey from uri string, optionally encrypts it with the user-provided password.
    #[pyo3(signature = (uri, use_password = true, overwrite = false, suppress = false))]
    pub fn create_coldkey_from_uri(&mut self, uri: String, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Wallet> {
        let keypair = Keypair::create_from_uri(uri.as_str())?;

        if !suppress {
            match keypair.mnemonic()? {
                Some(m) => {
                    display_mnemonic_msg(m.clone(), "coldkey");
                }
                None => {}
            }
        }

        self.set_coldkey(keypair.clone(), use_password, overwrite, py)?;
        self.set_coldkeypub(keypair.clone(), false, overwrite, py)?;
        Ok(self.clone())
    }

    /// Creates hotkey from uri string, optionally encrypts it with the user-provided password.
    #[pyo3(signature = (uri, use_password = true, overwrite = false, suppress = false))]
    pub fn create_hotkey_from_uri(&mut self, uri: String, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Wallet> {
        let keypair = Keypair::create_from_uri(uri.as_str())?;

        if !suppress {
            match keypair.mnemonic()? {
                Some(m) => {
                    display_mnemonic_msg(m.clone(), "hotkey");
                }
                None => {}
            }
        }

        self.set_hotkey(keypair.clone(), use_password, overwrite, py)?;
        Ok(self.clone())
    }

    /// Unlocks the coldkey.
    pub fn unlock_coldkey(&mut self, py: Python) -> PyResult<Keypair> {
        if self._coldkey.is_none() {
            let coldkey_file = self.coldkey_file()?;
            self._coldkey = Some(coldkey_file.get_keypair(None, py)?);
        }
        let _coldkey = self._coldkey.clone().ok_or(pyo3::exceptions::PyOSError::new_err("Coldkey file doesn't exist."))?;
        Ok(_coldkey)
    }

    /// Unlocks the coldkeypub.
    pub fn unlock_coldkeypub(&mut self, py: Python) -> PyResult<Keypair> {
        if self._coldkeypub.is_none() {
            let coldkeypub_file = self.coldkeypub_file()?;
            self._coldkeypub = Some(coldkeypub_file.get_keypair(None, py)?);
        }
        let _coldkeypub = self._coldkeypub.clone().ok_or(pyo3::exceptions::PyOSError::new_err("Coldkey file doesn't exist."))?;
        Ok(_coldkeypub)
    }

    /// Unlocks the hotkey.
    pub fn unlock_hotkey(&mut self, py: Python) -> PyResult<Keypair> {
        if self._hotkey.is_none() {
            let hotkey_file = self.hotkey_file()?;
            self._hotkey = Some(hotkey_file.get_keypair(None, py)?);
        }
        let _hotkey = self._hotkey.clone().ok_or(pyo3::exceptions::PyOSError::new_err("Hotkey doesn't exist."))?;
        Ok(_hotkey)
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words = 12, use_password = true, overwrite = false, suppress = false))]
    pub fn new_coldkey(&mut self, n_words: usize, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Wallet> {
        self.create_new_coldkey(n_words, use_password, overwrite, suppress, py)
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words=12, use_password=true, overwrite=false, suppress=false))]
    fn create_new_coldkey(&mut self, n_words: usize, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Wallet> {
        let mnemonic = Keypair::generate_mnemonic(n_words)?;
        let keypair = Keypair::create_from_mnemonic(&mnemonic)?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "coldkey");
        }

        self.set_coldkey(keypair.clone(), use_password, overwrite, py)?;
        self.set_coldkeypub(keypair.clone(), use_password, overwrite, py)?;

        Ok(self.clone())
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words = 12, use_password = false, overwrite = false, suppress = false))]
    pub fn new_hotkey(&mut self, n_words: usize, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Wallet> {
        self.create_new_hotkey(n_words, use_password, overwrite, suppress, py)
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words=12, use_password=false, overwrite=false, suppress=false))]
    pub fn create_new_hotkey(&mut self, n_words: usize, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Wallet> {
        let mnemonic = Keypair::generate_mnemonic(n_words)?;
        let keypair = Keypair::create_from_mnemonic(&mnemonic)?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "hotkey");
        }

        self.set_hotkey(keypair.clone(), use_password, overwrite, py)?;
        Ok(self.clone())
    }

    /// Regenerates the coldkeypub from the passed ``ss58_address`` or public_key and saves the file. Requires either ``ss58_address`` or public_key to be passed.
    #[pyo3(signature = (ss58_address = None, public_key = None, overwrite = false))]
    pub fn regenerate_coldkeypub(&mut self, ss58_address: Option<String>, public_key: Option<String>, overwrite: bool, py: Python) -> PyResult<Self> {

        if ss58_address.is_none() && public_key.is_none() {
            return Err(pyo3::exceptions::PyValueError::new_err("Either ss58_address or public_key must be passed."));
        }

        // convert from Option<String> to &Bound<PyAny> for `is_valid_bittensor_address_or_public_key`
        let address_to_string = ss58_address.as_ref().or(public_key.as_ref());
        let binding_py_string = PyString::new_bound(py, address_to_string.unwrap().as_str());
        let address_to_check: &Bound<PyAny> = binding_py_string.as_ref();

        if !is_valid_bittensor_address_or_public_key(address_to_check)? {
            return Err(pyo3::exceptions::PyValueError::new_err(
                format!(
                    "Invalid {}.",
                    if ss58_address.is_some() { "ss58_address" } else { "public_key" }
                )
            ));
        }

        let keypair = Keypair::new(ss58_address, public_key, None, 42, None, 1)?;

        self.set_coldkeypub(keypair, overwrite, false, py)?;
        Ok(self.clone())
    }

    /// Regenerates the coldkey from the passed mnemonic or seed, or JSON encrypts it with the user's password and saves the file.
    #[pyo3(signature = (mnemonic=None, seed=None, json=None, use_password=true, overwrite=false, suppress=false))]
    pub fn regenerate_coldkey(&mut self, mnemonic: Option<String>, seed: Option<String>, json: Option<(String, String)>, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Self> {
        let keypair = if let Some(mnemonic) = mnemonic {
            // mnemonic
            let keypair = Keypair::create_from_mnemonic(&mnemonic)?;
            if !suppress {
                display_mnemonic_msg(mnemonic, "coldkey");
            }
            keypair
        } else if let Some(seed) = seed {
            // seed
            Keypair::create_from_seed(&seed)?
        } else if let Some((json_data, passphrase)) = json {
            // json_data + passphrase
            Keypair::create_from_encrypted_json(&json_data, &passphrase)?
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err("Must pass either mnemonic, seed, or json."));
        };

        self.set_coldkey(keypair.clone(), use_password, overwrite, py)?;
        self.set_coldkeypub(keypair.clone(), false, overwrite, py)?;
        Ok(self.clone())
    }

    /// Regenerates the hotkey from passed mnemonic or seed, encrypts it with the user's password and saves the file.
    #[pyo3(signature = (mnemonic=None, seed=None, json=None, use_password=true, overwrite=false, suppress=false))]
    pub fn regenerate_hotkey(&mut self, mnemonic: Option<String>, seed: Option<String>, json: Option<(String, String)>, use_password: bool, overwrite: bool, suppress: bool, py: Python) -> PyResult<Self> {
        let keypair = if let Some(mnemonic) = mnemonic {
            // mnemonic
            let keypair = Keypair::create_from_mnemonic(&mnemonic)?;
            if !suppress {
                display_mnemonic_msg(mnemonic, "hotkey");
            }
            keypair
        } else if let Some(seed) = seed {
            // seed
            Keypair::create_from_seed(&seed)?
        } else if let Some((json_data, passphrase)) = json {
            // json_data + passphrase
            Keypair::create_from_encrypted_json(&json_data, &passphrase)?
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err("Must pass either mnemonic, seed, or json."));
        };

        self.set_hotkey(keypair, use_password, overwrite, py)?;

        Ok(self.clone())
    }
}
