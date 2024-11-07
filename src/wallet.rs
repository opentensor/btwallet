use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyString, PyType};

use colored::Colorize;
use std::env;
use std::path::PathBuf;

use crate::config::Config;
use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use crate::errors::KeyFileError;
use crate::keyfile::Keyfile;
use crate::keypair::Keypair;
use crate::utils::{self, is_valid_bittensor_address_or_public_key};

/// Display the mnemonic and a warning message to keep the mnemonic safe.
#[pyfunction]
#[pyo3(signature = (mnemonic, key_type))]
pub fn display_mnemonic_msg(mnemonic: String, key_type: &str) {
    utils::print(format!("{}", "\nIMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.\n".red()));

    utils::print(format!(
        "\nThe mnemonic to the new {} is: {}",
        key_type.blue(),
        mnemonic.green()
    ));
    utils::print(format!(
        "\nYou can use the mnemonic to recreate the key with `{}` in case it gets lost.\n",
        "btcli".green()
    ));
}

// Function to safely retrieve attribute as Option<String> from passed python object
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

#[derive(Clone)]
#[pyclass(subclass)]
pub struct Wallet {
    pub name: String,
    pub path: String,
    pub hotkey: String,

    _path: PathBuf,

    _coldkey: Option<Keypair>,
    _coldkeypub: Option<Keypair>,
    _hotkey: Option<Keypair>,
}

#[pymethods]
impl Wallet {
    /// Initialize the bittensor wallet object containing a hot and coldkey.
    ///
    ///     Args:
    ///         name (str, optional): The name of the wallet to unlock for running bittensor. Defaults to ``default``.
    ///         hotkey (str, optional): The name of hotkey used to running the miner. Defaults to ``default``.
    ///         path (str, optional): The path to your bittensor wallets. Defaults to ``~/.bittensor/wallets/``.
    ///         config (Config, optional): config.Config(). Defaults to ``None``.
    #[new]
    #[pyo3(signature = (name = None, hotkey = None, path = None, config = None))]
    fn new(
        name: Option<String>,
        hotkey: Option<String>,
        path: Option<String>,
        config: Option<PyObject>,
        py: Python,
    ) -> PyResult<Wallet> {
        // default config's values if config and config.wallet exist
        let mut conf_name: Option<String> = None;
        let mut conf_hotkey: Option<String> = None;
        let mut conf_path: Option<String> = None;

        // parse python config object if passed
        if let Some(config_obj) = config {
            let config_ref = config_obj.bind(py);

            // parse python config.wallet object if exist in config object
            if config_ref.hasattr("wallet")? {
                let wallet_obj = config_ref.getattr("wallet")?;

                if !wallet_obj.is_none() {
                    let wallet_ref = wallet_obj.as_ref();

                    // assign values instead of default ones
                    conf_name = get_attribute_string(py, wallet_ref, "name")?;
                    conf_hotkey = get_attribute_string(py, wallet_ref, "hotkey")?;
                    conf_path = get_attribute_string(py, wallet_ref, "path")?;
                }
            }
        }

        let final_name = if let Some(name) = name {
            name
        } else if let Some(conf_name) = conf_name {
            conf_name
        } else {
            BT_WALLET_NAME.to_string()
        };

        let final_hotkey = if let Some(hotkey) = hotkey {
            hotkey
        } else if let Some(conf_hotkey) = conf_hotkey {
            conf_hotkey
        } else {
            BT_WALLET_HOTKEY.to_string()
        };

        let final_path = if let Some(path) = path {
            path
        } else if let Some(conf_path) = conf_path {
            conf_path
        } else {
            BT_WALLET_PATH.to_string()
        };

        let expanded_path: PathBuf = PathBuf::from(shellexpand::tilde(&final_path).to_string());

        Ok(Wallet {
            name: final_name,
            hotkey: final_hotkey,
            path: final_path.clone(),

            _path: expanded_path,

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
    pub fn config(_: &Bound<'_, PyType>) -> PyResult<Config> {
        Config::new(None, None, None)
    }

    /// Print help to stdout.
    #[classmethod]
    pub fn help(_: &Bound<'_, PyType>) -> PyResult<Config> {
        unimplemented!()
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
        let default_path = env::var("BT_WALLET_PATH")
            .unwrap_or_else(|_| format!("~/{}", BT_WALLET_PATH.to_string()));

        let prefix_str = if let Some(value) = prefix {
            format!("\"{}\"", value)
        } else {
            "None".to_string()
        };

        let code = format!(
            r#"
prefix = {}
prefix_str = "" if prefix is None else prefix + "."

try:
    parser.add_argument(
        "--" + prefix_str + "wallet.name",
        required=False,
        default="{}",
        help="The name of the wallet to unlock for running bittensor "
        "(name mock is reserved for mocking this wallet)",
    )
    parser.add_argument(
        "--" + prefix_str + "wallet.hotkey",
        required=False,
        default="{}",
        help="The name of the wallet's hotkey.",
    )
    parser.add_argument(
        "--" + prefix_str + "wallet.path",
        required=False,
        default="{}",
        help="The path to your bittensor wallets",
    )
except argparse.ArgumentError:
    pass"#,
            prefix_str, default_name, default_hotkey, default_path
        );

        py.run_bound(
            &code,
            Some(&[("parser", parser)].into_py_dict_bound(py)),
            None,
        )
        .expect("Python parser parse failed.");
        Ok(parser.to_object(py))
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false, save_coldkey_to_env=false, save_hotkey_to_env=false, coldkey_password=None, hotkey_password=None, overwrite=false, suppress=false))]
    pub fn create_if_non_existent(
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
    ) -> PyResult<Wallet> {
        self.create(
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
    #[allow(clippy::bool_comparison)]
    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false, save_coldkey_to_env=false, save_hotkey_to_env=false, coldkey_password=None, hotkey_password=None, overwrite=false, suppress=false))]
    pub fn create(
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
        if overwrite
            || self.coldkey_file()?.exists_on_device()? == false
                && self.coldkeypub_file()?.exists_on_device()? == false
        {
            self.create_new_coldkey(
                12,
                coldkey_use_password,
                overwrite,
                suppress,
                save_coldkey_to_env,
                coldkey_password,
                py,
            )?;
        } else {
            utils::print(format!(
                "ColdKey for the wallet '{}' already exists.\n",
                self.name
            ));
        }

        if overwrite || !self.hotkey_file()?.exists_on_device()? {
            self.create_new_hotkey(
                12,
                hotkey_use_password,
                overwrite,
                suppress,
                save_hotkey_to_env,
                hotkey_password,
                py,
            )?;
        } else {
            utils::print(format!(
                "HotKey for the wallet '{}' already exists.\n",
                self.name
            ));
        }

        Ok(self.clone())
    }

    /// Checks for existing coldkeypub and hotkeys, and recreates them if non-existent.
    ///
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
    pub fn recreate(
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
    ) -> PyResult<Wallet> {
        self.create_new_coldkey(
            12,
            coldkey_use_password,
            overwrite,
            suppress,
            save_coldkey_to_env,
            coldkey_password,
            py,
        )?;
        self.create_new_hotkey(
            12,
            hotkey_use_password,
            overwrite,
            suppress,
            save_hotkey_to_env,
            hotkey_password,
            py,
        )?;

        Ok(self.clone())
    }

    /// Property that returns the hotkey file.
    #[getter]
    pub fn hotkey_file(&self) -> PyResult<Keyfile> {
        self.create_hotkey_file(false)
    }

    /// Created Hot Keyfile for Keypair
    #[pyo3(signature = (save_hotkey_to_env=false))]
    pub fn create_hotkey_file(&self, save_hotkey_to_env: bool) -> PyResult<Keyfile> {
        // concatenate wallet path
        let wallet_path = self._path.join(&self.name);

        // concatenate hotkey path
        let hotkey_path = wallet_path.join("hotkeys").join(&self.hotkey);

        Keyfile::new(
            hotkey_path.to_string_lossy().into_owned(),
            Some(self.hotkey.clone()),
            save_hotkey_to_env,
        )
    }

    /// Property that returns the coldkey file.
    #[getter]
    pub fn coldkey_file(&self) -> PyResult<Keyfile> {
        self.create_coldkey_file(false)
    }

    /// Created Cold Keyfile for Keypair
    #[pyo3(signature = (save_coldkey_to_env=false))]
    pub fn create_coldkey_file(&self, save_coldkey_to_env: bool) -> PyResult<Keyfile> {
        // concatenate wallet path
        let wallet_path = PathBuf::from(&self._path).join(&self.name);

        // concatenate coldkey path
        let coldkey_path = wallet_path.join("coldkey");
        Keyfile::new(
            coldkey_path.to_string_lossy().into_owned(),
            Some("coldkey".to_string()),
            save_coldkey_to_env,
        )
    }

    /// Property that returns the coldkeypub file.
    #[getter]
    pub fn coldkeypub_file(&self) -> PyResult<Keyfile> {
        // concatenate wallet path
        let wallet_path = self._path.join(&self.name);

        // concatenate hotkey path
        let coldkeypub_path = wallet_path.join("coldkeypub.txt");

        Keyfile::new(
            coldkeypub_path.to_string_lossy().into_owned(),
            Some("coldkeypub.txt".parse()?),
            false,
        )
    }

    /// Loads the coldkey from wallet.path/wallet.name/coldkey or raises an error.
    #[getter(coldkey)]
    pub fn coldkey_py_property(&self, py: Python) -> PyResult<Keypair> {
        if let Some(coldkey) = &self._coldkey {
            Ok(coldkey.clone())
        } else {
            self.get_coldkey(None, py)
        }
    }

    /// Loads the coldkeypub from wallet.path/wallet.name/coldkeypub.txt or raises an error.
    #[getter(coldkeypub)]
    pub fn coldkeypub_py_property(&self, py: Python) -> PyResult<Keypair> {
        self.get_coldkeypub(None, py)
    }

    /// Loads the hotkey from wallet.path/wallet.name/hotkeys/wallet.hotkey or raises an error.
    #[getter(hotkey)]
    pub fn hotkey_py_property(&self, py: Python) -> PyResult<Keypair> {
        if let Some(hotkey) = &self._hotkey {
            Ok(hotkey.clone())
        } else {
            self.get_hotkey(None, py)
        }
    }

    /// Loads the name from wallet.path/wallet.name/coldkeypub.txt or raises an error.
    #[getter(name)]
    pub fn get_name(&self) -> PyResult<String> {
        Ok(self.name.clone())
    }

    /// Loads the name from wallet.path/wallet.name/coldkeypub.txt or raises an error.
    #[getter(path)]
    pub fn get_path(&self) -> PyResult<String> {
        Ok(self.path.clone())
    }

    /// Loads the name from wallet.path/wallet.name/coldkeypub.txt or raises an error.
    #[getter(hotkey_str)]
    pub fn get_hotkey_str(&self) -> PyResult<String> {
        Ok(self.hotkey.clone())
    }

    /// Sets the hotkey for the wallet.
    #[pyo3(signature = (keypair, encrypt=true, overwrite=false, save_coldkey_to_env=false, coldkey_password=None))]
    pub fn set_coldkey(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
        py: Python,
    ) -> PyResult<()> {
        self._coldkey = Some(keypair.clone());
        self.create_coldkey_file(save_coldkey_to_env)?.set_keypair(
            keypair,
            encrypt,
            overwrite,
            coldkey_password,
            py,
        )
    }

    /// Sets the coldkeypub for the wallet.
    #[pyo3(signature = (keypair, encrypt=false, overwrite=false))]
    pub fn set_coldkeypub(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        py: Python,
    ) -> PyResult<()> {
        let _ss58_address = keypair.ss58_address()?.unwrap();
        let _coldkeypub_keypair = Keypair::new(Some(_ss58_address), None, None, 42, None, 1)?;

        self._coldkeypub = Some(_coldkeypub_keypair.clone());
        self.coldkeypub_file()?.set_keypair(
            _coldkeypub_keypair.clone(),
            encrypt,
            overwrite,
            None,
            py,
        )
    }

    /// Sets the hotkey for the wallet.
    #[pyo3(signature = (keypair, encrypt=false, overwrite=false, save_hotkey_to_env=false, hotkey_password=None))]
    pub fn set_hotkey(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
        py: Python,
    ) -> PyResult<()> {
        self._hotkey = Some(keypair.clone());
        self.create_hotkey_file(save_hotkey_to_env)?.set_keypair(
            keypair.clone(),
            encrypt,
            overwrite,
            hotkey_password,
            py,
        )
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
    #[pyo3(signature = (uri, use_password = true, overwrite = false, suppress = false, save_coldkey_to_env=false, coldkey_password=None))]
    pub fn create_coldkey_from_uri(
        &mut self,
        uri: String,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
        py: Python,
    ) -> PyResult<Wallet> {
        let keypair = Keypair::create_from_uri(uri.as_str())?;

        if !suppress {
            if let Some(m) = keypair.mnemonic()? {
                display_mnemonic_msg(m.clone(), "coldkey");
            }
        }

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
            py,
        )?;
        self.set_coldkeypub(keypair.clone(), false, overwrite, py)?;
        Ok(self.clone())
    }

    /// Creates hotkey from uri string, optionally encrypts it with the user-provided password.
    #[pyo3(signature = (uri, use_password = true, overwrite = false, suppress = false, save_hotkey_to_env=false, hotkey_password=None))]
    pub fn create_hotkey_from_uri(
        &mut self,
        uri: String,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
        py: Python,
    ) -> PyResult<Wallet> {
        let keypair = Keypair::create_from_uri(uri.as_str())?;

        if !suppress {
            if let Some(m) = keypair.mnemonic()? {
                display_mnemonic_msg(m.clone(), "hotkey");
            }
        }

        self.set_hotkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
            py,
        )?;
        Ok(self.clone())
    }

    /// Unlocks the coldkey.
    pub fn unlock_coldkey(&mut self, py: Python) -> PyResult<Keypair> {
        if self._coldkey.is_none() {
            let coldkey_file = self.coldkey_file()?;
            self._coldkey = Some(coldkey_file.get_keypair(None, py)?);
        }
        let _coldkey = self
            ._coldkey
            .clone()
            .ok_or(PyErr::new::<KeyFileError, _>("Coldkey file doesn't exist."))?;
        Ok(_coldkey)
    }

    /// Unlocks the coldkeypub.
    pub fn unlock_coldkeypub(&mut self, py: Python) -> PyResult<Keypair> {
        if self._coldkeypub.is_none() {
            let coldkeypub_file = self.coldkeypub_file()?;
            self._coldkeypub = Some(coldkeypub_file.get_keypair(None, py)?);
        }
        let _coldkeypub = self
            ._coldkeypub
            .clone()
            .ok_or(PyErr::new::<KeyFileError, _>("Coldkey file doesn't exist."))?;
        Ok(_coldkeypub)
    }

    /// Unlocks the hotkey.
    pub fn unlock_hotkey(&mut self, py: Python) -> PyResult<Keypair> {
        if self._hotkey.is_none() {
            let hotkey_file = self.hotkey_file()?;
            self._hotkey = Some(hotkey_file.get_keypair(None, py)?);
        }
        let _hotkey = self
            ._hotkey
            .clone()
            .ok_or(PyErr::new::<KeyFileError, _>("Hotkey doesn't exist."))?;
        Ok(_hotkey)
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words = 12, use_password=true, overwrite=false, suppress=false, save_coldkey_to_env=false, coldkey_password=None))]
    pub fn new_coldkey(
        &mut self,
        n_words: usize,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
        py: Python,
    ) -> PyResult<Wallet> {
        self.create_new_coldkey(
            n_words,
            use_password,
            overwrite,
            suppress,
            save_coldkey_to_env,
            coldkey_password,
            py,
        )
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words=12, use_password=true, overwrite=false, suppress=false, save_coldkey_to_env=false, coldkey_password=None))]
    fn create_new_coldkey(
        &mut self,
        n_words: usize,
        mut use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
        py: Python,
    ) -> PyResult<Wallet> {
        let mnemonic = Keypair::generate_mnemonic(n_words)?;
        let keypair = Keypair::create_from_mnemonic(&mnemonic)?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "coldkey");
        }

        // if coldkey_password is passed then coldkey_use_password always is true
        use_password = if coldkey_password.is_some() {
            true
        } else {
            use_password
        };

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
            py,
        )?;
        self.set_coldkeypub(keypair.clone(), false, overwrite, py)?;

        Ok(self.clone())
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words = 12, use_password = false, overwrite = false, suppress = false, save_hotkey_to_env=false, hotkey_password=None))]
    pub fn new_hotkey(
        &mut self,
        n_words: usize,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
        py: Python,
    ) -> PyResult<Wallet> {
        self.create_new_hotkey(
            n_words,
            use_password,
            overwrite,
            suppress,
            save_hotkey_to_env,
            hotkey_password,
            py,
        )
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    #[pyo3(signature = (n_words=12, use_password=false, overwrite=false, suppress=false, save_hotkey_to_env=false, hotkey_password=None))]
    pub fn create_new_hotkey(
        &mut self,
        n_words: usize,
        mut use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
        py: Python,
    ) -> PyResult<Wallet> {
        let mnemonic = Keypair::generate_mnemonic(n_words)?;
        let keypair = Keypair::create_from_mnemonic(&mnemonic)?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "hotkey");
        }

        // if hotkey_password is passed then hotkey_use_password always is true
        use_password = if hotkey_password.is_some() {
            true
        } else {
            use_password
        };

        self.set_hotkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
            py,
        )?;
        Ok(self.clone())
    }

    /// Regenerates the coldkeypub from the passed ``ss58_address`` or public_key and saves the file. Requires either ``ss58_address`` or public_key to be passed.
    #[pyo3(signature = (ss58_address = None, public_key = None, overwrite = false))]
    pub fn regenerate_coldkeypub(
        &mut self,
        ss58_address: Option<String>,
        public_key: Option<String>,
        overwrite: bool,
        py: Python,
    ) -> PyResult<Self> {
        if ss58_address.is_none() && public_key.is_none() {
            return Err(PyErr::new::<PyValueError, _>(
                "Either ss58_address or public_key must be passed.",
            ));
        }

        // convert from Option<String> to &Bound<PyAny> for `is_valid_bittensor_address_or_public_key`
        let address_to_string = ss58_address.as_ref().or(public_key.as_ref());
        let binding_py_string = PyString::new_bound(py, address_to_string.unwrap().as_str());
        let address_to_check: &Bound<PyAny> = binding_py_string.as_ref();

        if !is_valid_bittensor_address_or_public_key(address_to_check)? {
            return Err(PyErr::new::<PyValueError, _>(format!(
                "Invalid {}.",
                if ss58_address.is_some() {
                    "ss58_address"
                } else {
                    "public_key"
                }
            )));
        }

        let keypair = Keypair::new(ss58_address, public_key, None, 42, None, 1)?;

        self.set_coldkeypub(keypair, false, overwrite, py)?;
        Ok(self.clone())
    }

    /// Regenerates the coldkey from the passed mnemonic or seed, or JSON encrypts it with the user's password and saves the file.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (mnemonic=None, seed=None, json=None, use_password=true, overwrite=false, suppress=false, save_coldkey_to_env=false, coldkey_password=None))]
    pub fn regenerate_coldkey(
        &mut self,
        mnemonic: Option<String>,
        seed: Option<String>,
        json: Option<(String, String)>,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
        py: Python,
    ) -> PyResult<Self> {
        let keypair = if let Some(mnemonic) = mnemonic {
            // mnemonic
            let keypair = Keypair::create_from_mnemonic(&mnemonic)?;
            if !suppress {
                display_mnemonic_msg(mnemonic, "coldkey");
            }
            keypair
        } else if let Some(seed) = seed {
            // seed
            let seed_string: &Bound<PyAny> = &PyString::new_bound(py, seed.as_str());
            Keypair::create_from_seed(&seed_string.clone())?
        } else if let Some((json_data, passphrase)) = json {
            // json_data + passphrase
            Keypair::create_from_encrypted_json(&json_data, &passphrase)?
        } else {
            return Err(PyErr::new::<PyValueError, _>(
                "Must pass either mnemonic, seed, or json.",
            ));
        };

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
            py,
        )?;
        self.set_coldkeypub(keypair.clone(), false, overwrite, py)?;
        Ok(self.clone())
    }

    /// Regenerates the hotkey from passed mnemonic or seed, encrypts it with the user's password and saves the file.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (mnemonic=None, seed=None, json=None, use_password=true, overwrite=false, suppress=false, save_hotkey_to_env=false, hotkey_password=None))]
    pub fn regenerate_hotkey(
        &mut self,
        mnemonic: Option<String>,
        seed: Option<String>,
        json: Option<(String, String)>,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
        py: Python,
    ) -> PyResult<Self> {
        let keypair = if let Some(mnemonic) = mnemonic {
            // mnemonic
            let keypair = Keypair::create_from_mnemonic(&mnemonic)?;
            if !suppress {
                display_mnemonic_msg(mnemonic, "hotkey");
            }
            keypair
        } else if let Some(seed) = seed {
            // seed
            let seed_string: &Bound<PyAny> = &PyString::new_bound(py, seed.as_str());
            Keypair::create_from_seed(&seed_string.clone())?
        } else if let Some((json_data, passphrase)) = json {
            // json_data + passphrase
            Keypair::create_from_encrypted_json(&json_data, &passphrase)?
        } else {
            return Err(PyErr::new::<PyValueError, _>(
                "Must pass either mnemonic, seed, or json.",
            ));
        };

        self.set_hotkey(
            keypair,
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
            py,
        )?;

        Ok(self.clone())
    }
}
