use colored::Colorize;
use pyo3::pyfunction;
use std::path::PathBuf;
use std::{env, fmt};

use crate::config::Config;
use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use crate::errors::*;
use crate::keyfile::Keyfile;
use crate::keypair::Keypair;
use crate::utils::{self, is_valid_bittensor_address_or_public_key};

/// Display the mnemonic and a warning message to keep the mnemonic safe.
#[pyfunction]
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

#[derive(Clone)]
pub struct Wallet {
    pub name: String,
    pub path: String,
    pub hotkey: String,

    _path: PathBuf,

    _coldkey: Option<Keypair>,
    _coldkeypub: Option<Keypair>,
    _hotkey: Option<Keypair>,
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Wallet (Name: '{:}', Hotkey: '{:}', Path: '{:}')",
            self.name, self.hotkey, self.path
        )
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "name: '{:?}', hotkey: '{:?}', path: '{:?}'",
            self.name, self.hotkey, self.path
        )
    }
}

impl Wallet {
    /// Initialize the bittensor wallet object containing a hot and coldkey.
    ///
    /// # Arguments
    /// * `name` - The name of the wallet. Defaults to "default"
    /// * `hotkey` - The name of hotkey. Defaults to "default"
    /// * `path` - The path to wallets. Defaults to "~/.bittensor/wallets/"
    /// * `config` - Optional configuration
    pub fn new(
        name: Option<String>,
        hotkey: Option<String>,
        path: Option<String>,
        config: Option<Config>,
    ) -> Self {
        let final_name = name
            .or(config.as_ref().map(|conf| conf.name()))
            .unwrap_or(BT_WALLET_NAME.to_string());

        let final_hotkey = hotkey
            .or(config.as_ref().map(|conf| conf.hotkey()))
            .unwrap_or(BT_WALLET_HOTKEY.to_string());

        let final_path = path
            .or(config.as_ref().map(|conf| conf.path()))
            .unwrap_or(BT_WALLET_PATH.to_string());

        let expanded_path = PathBuf::from(shellexpand::tilde(&final_path).to_string());

        Wallet {
            name: final_name,
            hotkey: final_hotkey,
            path: final_path,
            _path: expanded_path,
            _coldkey: None,
            _coldkeypub: None,
            _hotkey: None,
        }
    }

    /// Get default config
    pub fn config() -> Config {
        Config::new(None, None, None)
    }

    /// Print help information
    pub fn help() -> Config {
        unimplemented!()
    }

    // TODO: What are the prefixes for ?
    pub fn add_args(parser: clap::Command, _prefix: Option<&str>) -> clap::Command {
        let default_name =
            env::var("BT_WALLET_NAME").unwrap_or_else(|_| BT_WALLET_NAME.to_string());
        let default_name_static: &'static str = Box::leak(default_name.into_boxed_str());

        let parser = parser.arg(
            clap::Arg::new("wallet.name")
                .long("wallet.name")
                .default_value(default_name_static)
                .help("The name of the wallet to unlock for running Bittensor"),
        );

        let default_hotkey =
            env::var("BT_WALLET_HOTKEY").unwrap_or_else(|_| BT_WALLET_HOTKEY.to_string());
        let default_hotkey_static: &'static str = Box::leak(default_hotkey.into_boxed_str());

        let parser = parser.arg(
            clap::Arg::new("wallet.hotkey")
                .long("wallet.hotkey")
                .default_value(default_hotkey_static)
                .help("The name of the wallet's hotkey"),
        );

        let default_path =
            env::var("BT_WALLET_PATH").unwrap_or_else(|_| BT_WALLET_PATH.to_string());
        let default_path_static: &'static str = Box::leak(default_path.into_boxed_str());

        let parser = parser.arg(
            clap::Arg::new("wallet.path")
                .long("wallet.path")
                .default_value(default_path_static)
                .help("The path to your Bittensor wallets"),
        );

        parser
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
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
    ) -> Result<Self, WalletError> {
        self.create(
            coldkey_use_password,
            hotkey_use_password,
            save_coldkey_to_env,
            save_hotkey_to_env,
            coldkey_password,
            hotkey_password,
            overwrite,
            suppress,
        )
    }

    /// Checks for existing coldkeypub and hotkeys, and creates them if non-existent.
    ///
    /// # Arguments
    /// * `coldkey_use_password` - Whether to use a password for coldkey. Defaults to true.
    /// * `hotkey_use_password` - Whether to use a password for hotkey. Defaults to false.
    /// * `save_coldkey_to_env` - Whether to save coldkey password to local env. Defaults to false.
    /// * `save_hotkey_to_env` - Whether to save hotkey password to local env. Defaults to false.
    /// * `coldkey_password` - Optional password for coldkey encryption. If provided, forces password use.
    /// * `hotkey_password` - Optional password for hotkey encryption. If provided, forces password use.
    /// * `overwrite` - Whether to overwrite existing keys. Defaults to false.
    /// * `suppress` - Whether to suppress mnemonic display. Defaults to false.
    ///
    /// # Returns
    /// * `Result<Self, WalletError>` - Wallet instance with created keys or error
    #[allow(clippy::bool_comparison)]
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
    ) -> Result<Self, WalletError> {
        if overwrite
            || (!self.coldkey_file()?.exists_on_device()?
                && !self.coldkeypub_file()?.exists_on_device()?)
        {
            self.create_new_coldkey(
                12,
                coldkey_use_password,
                overwrite,
                suppress,
                save_coldkey_to_env,
                coldkey_password,
            )?;
        } else {
            println!("ColdKey for the wallet '{}' already exists.", self.name);
        }

        if overwrite || !self.hotkey_file()?.exists_on_device()? {
            self.create_new_hotkey(
                12,
                hotkey_use_password,
                overwrite,
                suppress,
                save_hotkey_to_env,
                hotkey_password,
            )?;
        } else {
            println!("HotKey for the wallet '{}' already exists.", self.name);
        }

        Ok(self.clone())
    }

    /// Checks for existing coldkeypub and hotkeys, and recreates them if non-existent.
    ///
    /// # Arguments
    /// * `coldkey_use_password` - Whether to use a password for coldkey. Defaults to true.
    /// * `hotkey_use_password` - Whether to use a password for hotkey. Defaults to false.
    /// * `save_coldkey_to_env` - Whether to save a coldkey password to local env. Defaults to false.
    /// * `save_hotkey_to_env` - Whether to save a hotkey password to local env. Defaults to false.
    /// * `coldkey_password` - Optional coldkey password for encryption. If provided, forces password use.
    /// * `hotkey_password` - Optional hotkey password for encryption. If provided, forces password use.
    /// * `overwrite` - Whether to overwrite existing keys. Defaults to false.
    /// * `suppress` - Whether to suppress mnemonic display. Defaults to false.
    ///
    /// # Returns
    /// * `Result<Self, WalletError>` - Wallet instance with created keys or error
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
    ) -> Result<Self, WalletError> {
        self.create_new_coldkey(
            12,
            coldkey_use_password,
            overwrite,
            suppress,
            save_coldkey_to_env,
            coldkey_password,
        )?;
        self.create_new_hotkey(
            12,
            hotkey_use_password,
            overwrite,
            suppress,
            save_hotkey_to_env,
            hotkey_password,
        )?;

        Ok(self.clone())
    }

    /// Returns the hotkey file.
    pub fn hotkey_file(&self) -> Result<Keyfile, KeyFileError> {
        self.create_hotkey_file(false)
    }

    /// Creates a new hotkey file for the keypair
    pub fn create_hotkey_file(&self, save_hotkey_to_env: bool) -> Result<Keyfile, KeyFileError> {
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

    /// Returns the coldkey file.
    pub fn coldkey_file(&self) -> Result<Keyfile, KeyFileError> {
        self.create_coldkey_file(false)
    }

    /// Creates a new coldkey file for the keypair
    pub fn create_coldkey_file(&self, save_coldkey_to_env: bool) -> Result<Keyfile, KeyFileError> {
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

    /// Returns the coldkeypub file.
    pub fn coldkeypub_file(&self) -> Result<Keyfile, KeyFileError> {
        // concatenate wallet path
        let wallet_path = self._path.join(&self.name);

        // concatenate hotkey path
        let coldkeypub_path = wallet_path.join("coldkeypub.txt");

        Keyfile::new(
            coldkeypub_path.to_string_lossy().into_owned(),
            Some("coldkeypub.txt".to_string()),
            false,
        )
    }

    /// Returns the coldkey from wallet.path/wallet.name/coldkey or raises an error.
    pub fn coldkey_property(&self) -> Result<Keypair, KeyFileError> {
        if let Some(coldkey) = &self._coldkey {
            Ok(coldkey.clone())
        } else {
            let coldkey_file = self.coldkey_file()?;
            coldkey_file.get_keypair(None)
        }
    }

    /// Returns the coldkeypub from wallet.path/wallet.name/coldkeypub.txt or raises an error.
    pub fn coldkeypub_property(&self) -> Result<Keypair, KeyFileError> {
        let coldkeypub_file = self.coldkeypub_file()?;
        coldkeypub_file.get_keypair(None)
    }

    /// Returns the hotkey from wallet.path/wallet.name/hotkeys/wallet.hotkey or raises an error.
    pub fn hotkey_property(&self) -> Result<Keypair, KeyFileError> {
        if let Some(hotkey) = &self._hotkey {
            Ok(hotkey.clone())
        } else {
            let hotkey_file = self.hotkey_file()?;
            hotkey_file.get_keypair(None)
        }
    }

    /// Returns the name of the wallet
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    /// Returns the path of the wallet
    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    /// Returns the hotkey name
    pub fn get_hotkey_str(&self) -> String {
        self.hotkey.clone()
    }

    /// Sets the coldkey for the wallet.
    ///
    /// # Arguments
    /// * `keypair` - The keypair to set as coldkey
    /// * `encrypt` - Whether to encrypt the key. Defaults to true
    /// * `overwrite` - Whether to overwrite if key exists. Defaults to false
    /// * `save_coldkey_to_env` - Whether to save password to env. Defaults to false
    /// * `coldkey_password` - Optional password for encryption
    ///
    /// # Returns
    /// * `Result<(), KeyFileError>` - Success or error
    pub fn set_coldkey(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<(), KeyFileError> {
        self._coldkey = Some(keypair.clone());
        match self.create_coldkey_file(save_coldkey_to_env) {
            Ok(keyfile) => keyfile
                .set_keypair(keypair, encrypt, overwrite, coldkey_password)
                .map_err(|e| KeyFileError::Generic(e.to_string())),
            Err(e) => Err(KeyFileError::Generic(e.to_string())),
        }
    }

    /// Sets the coldkeypub for the wallet.
    pub fn set_coldkeypub(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
    ) -> Result<(), KeyFileError> {
        let ss58_address = keypair
            .ss58_address()
            .ok_or_else(|| KeyFileError::Generic("Failed to get ss58_address".to_string()))?;
        let coldkeypub_keypair = Keypair::new(Some(ss58_address), None, None, 42, None, 1)
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;

        self._coldkeypub = Some(coldkeypub_keypair.clone());
        self.coldkeypub_file()
            .map_err(|e| KeyFileError::Generic(e.to_string()))?
            .set_keypair(coldkeypub_keypair, encrypt, overwrite, None)
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;
        Ok(())
    }

    /// Sets the hotkey for the wallet.
    pub fn set_hotkey(
        &mut self,
        keypair: Keypair,
        encrypt: bool,
        overwrite: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<(), KeyFileError> {
        self._hotkey = Some(keypair.clone());
        self.create_hotkey_file(save_hotkey_to_env)
            .map_err(|e| KeyFileError::Generic(e.to_string()))?
            .set_keypair(keypair, encrypt, overwrite, hotkey_password)
    }

    /// Gets the coldkey from the wallet.
    pub fn get_coldkey(&self, password: Option<String>) -> Result<Keypair, KeyFileError> {
        self.coldkey_file()?.get_keypair(password)
    }

    /// Gets the coldkeypub from the wallet.
    pub fn get_coldkeypub(&self, password: Option<String>) -> Result<Keypair, KeyFileError> {
        self.coldkeypub_file()?.get_keypair(password)
    }

    /// Gets the hotkey from the wallet.
    pub fn get_hotkey(&self, password: Option<String>) -> Result<Keypair, KeyFileError> {
        self.hotkey_file()?.get_keypair(password)
    }

    /// Creates coldkey from uri string, optionally encrypts it with the user-provided password.
    pub fn create_coldkey_from_uri(
        &mut self,
        uri: String,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<Wallet, KeyFileError> {
        let keypair = Keypair::create_from_uri(uri.as_str())
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;

        if !suppress {
            if let Some(m) = keypair.mnemonic() {
                display_mnemonic_msg(m, "coldkey");
            }
        }

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
        )?;
        self.set_coldkeypub(keypair, false, overwrite)?;
        Ok(self.clone())
    }

    /// Creates hotkey from uri string, optionally encrypts it with the user-provided password.
    pub fn create_hotkey_from_uri(
        &mut self,
        uri: String,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<Wallet, KeyFileError> {
        let keypair = Keypair::create_from_uri(uri.as_str())
            .map_err(|e| KeyFileError::Generic(e.to_string()))?;

        if !suppress {
            if let Some(m) = keypair.mnemonic() {
                display_mnemonic_msg(m, "hotkey");
            }
        }

        self.set_hotkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
        )?;
        Ok(self.clone())
    }

    /// Unlocks the coldkey.
    pub fn unlock_coldkey(&mut self) -> Result<Keypair, KeyFileError> {
        if self._coldkey.is_none() {
            let coldkey_file = self.coldkey_file()?;
            self._coldkey = Some(coldkey_file.get_keypair(None)?);
        }
        let _coldkey = self
            ._coldkey
            .clone()
            .ok_or_else(|| KeyFileError::Generic("Coldkey file doesn't exist.".to_string()))?;
        Ok(_coldkey)
    }

    /// Unlocks the coldkeypub.
    pub fn unlock_coldkeypub(&mut self) -> Result<Keypair, KeyFileError> {
        if self._coldkeypub.is_none() {
            let coldkeypub_file = self.coldkeypub_file()?;
            self._coldkeypub = Some(coldkeypub_file.get_keypair(None)?);
        }
        let _coldkeypub = self
            ._coldkeypub
            .clone()
            .ok_or_else(|| KeyFileError::Generic("Coldkey file doesn't exist.".to_string()))?;
        Ok(_coldkeypub)
    }

    /// Unlocks the hotkey.
    pub fn unlock_hotkey(&mut self) -> Result<Keypair, KeyFileError> {
        if self._hotkey.is_none() {
            let hotkey_file = self.hotkey_file()?;
            self._hotkey = Some(hotkey_file.get_keypair(None)?);
        }
        let _hotkey = self
            ._hotkey
            .clone()
            .ok_or_else(|| KeyFileError::Generic("Hotkey doesn't exist.".to_string()))?;
        Ok(_hotkey)
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    pub fn new_coldkey(
        &mut self,
        n_words: usize,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<Wallet, WalletError> {
        self.create_new_coldkey(
            n_words,
            use_password,
            overwrite,
            suppress,
            save_coldkey_to_env,
            coldkey_password,
        )
    }

    /// Creates a new coldkey, optionally encrypts it with the user-provided password and saves to disk.
    fn create_new_coldkey(
        &mut self,
        n_words: usize,
        mut use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_coldkey_to_env: bool,
        coldkey_password: Option<String>,
    ) -> Result<Self, WalletError> {
        let mnemonic = Keypair::generate_mnemonic(n_words)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        let keypair = Keypair::create_from_mnemonic(&mnemonic)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "coldkey");
        }

        // If password is provided, force password usage
        if coldkey_password.is_some() {
            use_password = true;
        }

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
        )?;

        self.set_coldkeypub(keypair.clone(), false, overwrite)?;

        Ok(self.clone())
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    pub fn new_hotkey(
        &mut self,
        n_words: usize,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<Self, WalletError> {
        self.create_new_hotkey(
            n_words,
            use_password,
            overwrite,
            suppress,
            save_hotkey_to_env,
            hotkey_password,
        )
    }

    /// Creates a new hotkey, optionally encrypts it with the user-provided password and saves to disk.
    pub fn create_new_hotkey(
        &mut self,
        n_words: usize,
        mut use_password: bool,
        overwrite: bool,
        suppress: bool,
        save_hotkey_to_env: bool,
        hotkey_password: Option<String>,
    ) -> Result<Wallet, WalletError> {
        let mnemonic = Keypair::generate_mnemonic(n_words)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;
        let keypair = Keypair::create_from_mnemonic(&mnemonic)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        if !suppress {
            display_mnemonic_msg(mnemonic, "hotkey");
        }

        // if hotkey_password is passed then hotkey_use_password always is true
        use_password = hotkey_password.is_some() || use_password;

        self.set_hotkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
        )?;
        Ok(self.clone())
    }

    /// Regenerates the coldkeypub from the passed ss58_address or public_key and saves the file.
    /// Requires either ss58_address or public_key to be passed.
    pub fn regenerate_coldkeypub(
        &mut self,
        ss58_address: Option<String>,
        public_key: Option<String>,
        overwrite: bool,
    ) -> Result<Self, WalletError> {
        if ss58_address.is_none() && public_key.is_none() {
            return Err(WalletError::InvalidInput(
                "Either ss58_address or public_key must be passed.".to_string(),
            ));
        }

        let address_to_string = ss58_address
            .as_ref()
            .or(public_key.as_ref())
            .ok_or_else(|| WalletError::InvalidInput("No address provided".to_string()))?;

        if !is_valid_bittensor_address_or_public_key(address_to_string) {
            return Err(WalletError::InvalidInput(format!(
                "Invalid {}.",
                if ss58_address.is_some() {
                    "ss58_address"
                } else {
                    "public_key"
                }
            )));
        }

        let keypair = Keypair::new(ss58_address, public_key, None, 42, None, 1)
            .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;

        self.set_coldkeypub(keypair, false, overwrite)?;
        Ok(self.clone())
    }

    /// Regenerates the coldkey from the passed mnemonic or seed, or JSON encrypts it with the user's password and saves the file.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<Self, WalletError> {
        let keypair = if let Some(mnemonic) = mnemonic {
            // mnemonic
            let keypair = Keypair::create_from_mnemonic(&mnemonic)
                .map_err(|e| WalletError::KeyGeneration(e.to_string()))?;
            if !suppress {
                display_mnemonic_msg(mnemonic, "coldkey");
            }
            keypair
        } else if let Some(seed) = seed {
            // seed
            Keypair::create_from_seed(hex::decode(seed).unwrap())
                .map_err(|e| KeyFileError::Generic(e.to_string()))?
        } else if let Some((json_data, passphrase)) = json {
            // json_data + passphrase
            Keypair::create_from_encrypted_json(&json_data, &passphrase)
                .map_err(|e| KeyFileError::Generic(e.to_string()))?
        } else {
            return Err(WalletError::InvalidInput(
                "Must pass either mnemonic, seed, or json.".to_string(),
            ));
        };

        self.set_coldkey(
            keypair.clone(),
            use_password,
            overwrite,
            save_coldkey_to_env,
            coldkey_password,
        )?;
        self.set_coldkeypub(keypair.clone(), false, overwrite)?;
        Ok(self.clone())
    }

    /// Regenerates the hotkey from passed mnemonic or seed, encrypts it with the user's password and saves the file.
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
    ) -> Result<Self, KeyFileError> {
        let keypair = if let Some(mnemonic) = mnemonic {
            // mnemonic
            let keypair = Keypair::create_from_mnemonic(&mnemonic)
                .map_err(|e| KeyFileError::Generic(e.to_string()))?;
            if !suppress {
                display_mnemonic_msg(mnemonic, "hotkey");
            }
            keypair
        } else if let Some(seed) = seed {
            // seed
            Keypair::create_from_seed(hex::decode(seed).unwrap())
                .map_err(|e| KeyFileError::Generic(e.to_string()))?
        } else if let Some((json_data, passphrase)) = json {
            // json_data + passphrase
            Keypair::create_from_encrypted_json(&json_data, &passphrase)
                .map_err(|e| KeyFileError::Generic(e.to_string()))?
        } else {
            return Err(KeyFileError::Generic(
                "Must pass either mnemonic, seed, or json.".to_string(),
            ));
        };

        self.set_hotkey(
            keypair,
            use_password,
            overwrite,
            save_hotkey_to_env,
            hotkey_password,
        )?;

        Ok(self.clone())
    }
}
