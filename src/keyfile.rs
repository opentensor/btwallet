use crate::keypair::{load_keypair, Pair};
use pyo3::prelude::*;
use shellexpand;
use std::path::PathBuf;

pub struct Keyfile {
    name: String,
    path: PathBuf,
    password: Option<String>,
    mnemonic: Option<String>,
}

#[derive(Debug)]
pub enum KeyfileType {
    Hotkey,
    Coldkey,
    Coldkeypub,
}

impl Keyfile {
    /// Creates a new Keyfile instance.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the keyfile.
    /// * `path` - The path to the keyfile.
    /// * `password` - An optional password for the keyfile.
    /// * `mnemonic` - An optional mnemonic phrase for the keyfile.
    ///
    /// # Returns
    ///
    /// A new `Keyfile` instance.
    pub fn new(
        name: String,
        path: PathBuf,
        password: Option<String>,
        mnemonic: Option<String>,
    ) -> Self {
        Keyfile {
            name,
            path,
            password,
            mnemonic,
        }
    }

    fn path(&self) -> PyResult<String> {
        Ok(self.path.to_string_lossy().into_owned())
    }

    fn load_hotkey(&self) -> Pair {
        let keypair = load_keypair(&self.name, "hotkey", &self.password, &self.mnemonic)
            .expect("Failed to load hotkey");
        keypair
    }

    fn load_coldkey(&self) -> Pair {
        let keypair = load_keypair(&self.name, "coldkey", &self.password, &self.mnemonic)
            .expect("Failed to load coldkey");
        keypair
    }

    fn load_coldkeypub(&self) -> Pair {
        let keypair = load_keypair(&self.name, "coldkeypub", &self.password, &self.mnemonic)
            .expect("Failed to load coldkeypub");
        keypair
    }

    pub fn coldkey_pub_file(&self) -> PathBuf {
        let wallet_path = PathBuf::from(
            shellexpand::tilde(&self.path.to_string_lossy().into_owned()).into_owned(),
        )
        .join("coldkeypub.txt");
        wallet_path
    }
    pub fn hotkey_file(&self) -> PathBuf {
        let wallet_path = PathBuf::from(
            shellexpand::tilde(&self.path.to_string_lossy().into_owned()).into_owned(),
        )
        .join("hotkeys")
        .join("hotkey");
        wallet_path
    }

    pub fn coldkey_file(&self) -> PathBuf {
        let wallet_path = PathBuf::from(
            shellexpand::tilde(&self.path.to_string_lossy().into_owned()).into_owned(),
        )
        .join("coldkey");
        wallet_path
    }
}
