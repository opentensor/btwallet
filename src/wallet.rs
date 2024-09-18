use pyo3::prelude::*;
use std::path::PathBuf;
use pyo3::prelude::*;
use pyo3::exceptions::PyException;
use serde::{Deserialize, Serialize};
use std::fmt;
use pyo3::create_exception;
use crate::keypair::Keypair;


const BT_WALLET_NAME: &str = "default";
pub const BT_WALLET_PATH: &str = "~/.bittensor/wallets/";

#[pyclass]
pub struct Keyfile {
    path: PathBuf,
}

#[pymethods]
impl Keyfile {
    #[new]
    fn new(path: PathBuf) -> Self {
        Keyfile { path }
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.path.to_string_lossy().into_owned())
    }
}

#[derive(Debug)]
pub enum WalletError {
    KeyError(String),
    ConfigError(String),
    IOError(String),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::KeyError(msg) => write!(f, "Key Error: {}", msg),
            WalletError::ConfigError(msg) => write!(f, "Config Error: {}", msg),
            WalletError::IOError(msg) => write!(f, "IO Error: {}", msg),
        }
    }
}

impl std::error::Error for WalletError {}

create_exception!(wallet, WalletException, PyException);


#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub wallet: WalletConfig,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub name: String,
    pub hotkey: String,
    pub path: String,
}
#[pyclass]
pub struct Wallet {
    config: Config,
    name: String,
    path: String,
    hotkey_str: String,
    #[pyo3(get, set)]
    _hotkey: Option<Keypair>,
    #[pyo3(get, set)]
    _coldkey: Option<Keypair>,
    #[pyo3(get, set)]
    _coldkeypub: Option<Keypair>,
}

#[pymethods]
impl Wallet {
    // #[new]
    // #[pyo3(signature = (name = None, path = None))]
    // fn new(name: Option<String>, path: Option<String>) -> PyResult<Self> {
    //     Ok(Wallet {
    //         name: name.unwrap_or_else(|| BT_WALLET_NAME.to_string()),
    //         path: path
    //             .map(PathBuf::from)
    //             .unwrap_or_else(|| PathBuf::from(BT_WALLET_PATH)),
    //     })
    // }

    #[new]
    fn new(name: Option<String>, hotkey: Option<String>, path: Option<String>, config: Option<Config>) -> Result<Self, WalletError> {
        let mut config = config.unwrap_or_else(|| Self::default_config());

        config.wallet.name = name.unwrap_or_else(|| config.wallet.name.clone());
        config.wallet.hotkey = hotkey.unwrap_or_else(|| config.wallet.hotkey.clone());
        config.wallet.path = path.unwrap_or_else(|| config.wallet.path.clone());

        Ok(Wallet {
            name: config.wallet.name.clone(),
            path: config.wallet.path.clone(),
            hotkey_str: config.wallet.hotkey.clone(),
            config,
            _hotkey: None,
            _coldkey: None,
            _coldkeypub: None,
        })
    }

    fn config(&self) -> Result<Config, WalletError> {
        Ok(self.config.clone())
    }

    fn hotkey_file(&self) -> Result<PathBuf, WalletError> {
        Ok(PathBuf::from(format!("{}/hotkey.json", self.path)))
    }

    fn coldkey_file(&self) -> Result<PathBuf, WalletError> {
        Ok(PathBuf::from(format!("{}/coldkey.json", self.path)))
    }

    // #[getter]
    // fn coldkey_file(&self) -> PyResult<Keyfile> {
    //     let wallet_path = self.wallet_path();
    //     let coldkey_path = wallet_path.join("coldkey");
    //     Ok(Keyfile::new(coldkey_path))
    // }

    // #[getter]
    // fn coldkeypub_file(&self) -> PyResult<Keyfile> {
    //     let wallet_path = self.wallet_path();
    //     let coldkeypub_path = wallet_path.join("coldkeypub.txt");
    //     Ok(Keyfile::new(coldkeypub_path))
    // }

    fn wallet_path(&self) -> PathBuf {
        self.path.join(&self.name)
    }

   fn coldkeypub_file(&self) -> Result<PathBuf, WalletError> {
        Ok(PathBuf::from(format!("{}/coldkeypub.txt", self.path)))
    }

    fn set_hotkey(&mut self, hotkey: Keypair) -> Result<(), WalletError> {
        self._hotkey = Some(hotkey);
        Ok(())
    }

    fn set_coldkey(&mut self, coldkey: Keypair) -> Result<(), WalletError> {
        self._coldkey = Some(coldkey);
        Ok(())
    }

    fn set_coldkeypub(&mut self, coldkeypub: Keypair) -> Result<(), WalletError> {
        self._coldkeypub = Some(coldkeypub);
        Ok(())
    }

    fn get_hotkey(&self) -> Result<Option<&Keypair>, WalletError> {
        Ok(self._hotkey.as_ref())
    }

    fn get_coldkey(&self) -> Result<Option<&Keypair>, WalletError> {
        Ok(self._coldkey.as_ref())
    }

    fn get_coldkeypub(&self) -> Result<Option<&Keypair>, WalletError> {
        Ok(self._coldkeypub.as_ref())
    }

    fn unlock_hotkey(&self) -> Result<Keypair, WalletError> {
        Ok(Keypair)  // Placeholder logic
    }

    fn unlock_coldkey(&self) -> Result<Keypair, WalletError> {
        Ok(Keypair)  // Placeholder logic
    }

    fn unlock_coldkeypub(&self) -> Result<Keypair, WalletError> {
        Ok(Keypair)  // Placeholder logic
    }

    fn new_hotkey(&self) -> Result<Keypair, WalletError> {
        Ok(Keypair)  // Placeholder logic
    }

    fn new_coldkey(&self) -> Result<Keypair, WalletError> {
        Ok(Keypair)  // Placeholder logic
    }

    fn regenerate_hotkey(&self) -> Result<Keypair, WalletError> {
        Ok(Keypair)  // Placeholder logic
    }

    fn regenerate_coldkey(&self) -> Result<Keypair, WalletError> {
        Ok(Keypair)  // Placeholder logic
    }

    fn regenerate_coldkeypub(&self) -> Result<Keypair, WalletError> {
        Ok(Keypair)  // Placeholder logic
    }

    #[getter]
    fn name(&self) -> PyResult<String> {
        Ok(self.name.clone())
    }

    #[getter]
    fn path(&self) -> PyResult<String> {
        Ok(self.path.to_string_lossy().into_owned())
    }
}

impl Wallet {
    pub fn default_config() -> Config {
        Config {
            wallet: WalletConfig {
                name: String::from("default"),
                hotkey: String::from("default"),
                path: String::from("~/.bittensor/wallets/"),
            }
        }
    }
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Wallet(name: {}, hotkey: {}, path: {})", self.name, self.hotkey_str, self.path)
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wallet(name: {:?}, hotkey: {:?}, path: {:?})", self.name, self.hotkey_str, self.path)
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keypair")
    }
}