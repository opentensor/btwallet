use crate::config::Config;
use crate::constants::{BT_WALLET_HOTKEY, BT_WALLET_NAME, BT_WALLET_PATH};
use crate::keypair::Keypair;
use colored::Colorize;
use pyo3::prelude::*;

#[pyclass(name = "Wallet", get_all)]
pub struct Wallet {
    pub name: String,
    pub path: String,
    pub hotkey: String,
    pub config: Option<Config>,
}

#[pymethods]
impl Wallet {
    #[new]
    #[pyo3(signature = (name = None, hotkey = None, path = None, config = None))]
    fn new(
        name: Option<String>,
        hotkey: Option<String>,
        path: Option<String>,
        config: Option<Config>,
    ) -> Self {

        Wallet {
            name: name.unwrap_or_else(|| BT_WALLET_NAME.to_string()),
            hotkey: hotkey.unwrap_or_else(|| BT_WALLET_HOTKEY.to_string()),
            path: path.unwrap_or_else(|| BT_WALLET_PATH.to_string()),
            config: config.or(None),
        }
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

    #[pyo3(signature = (coldkey_use_password=true, hotkey_use_password=false))]
    fn create(&self, coldkey_use_password: bool, hotkey_use_password: bool) -> PyResult<Self> {
        println!(
            ">>> create {:?}, {:?}",
            coldkey_use_password, hotkey_use_password
        );
        Ok(Wallet::new(None, None, None, None))
    }

    #[pyo3(signature = (n_words=12, use_password=true, overwrite=false, suppress=false))]
    fn create_new_coldkey(
        &self,
        n_words: usize,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
    ) -> PyResult<Self> {
        println!(
            ">>> create_new_coldkey {:?}, {:?}, {:?}, {:?}",
            n_words, use_password, overwrite, suppress
        );

        //+ mnemonic = Keypair.generate_mnemonic(n_words)
        //+ keypair = Keypair.create_from_mnemonic(mnemonic)
        //+ if not suppress:
        //+     display_mnemonic_msg(keypair, "coldkey")

        // self.set_coldkey(keypair, encrypt=use_password, overwrite=overwrite)
        // self.set_coldkeypub(keypair, overwrite=overwrite)

        let mnemonic = Keypair::generate_mnemonic(n_words)?;
        let _keypair = Keypair::create_from_mnemonic(mnemonic.clone().as_str())?;

        if !suppress {
            self.display_mnemonic_msg(mnemonic.clone(), "coldkey");
        }

        // Ok((n_words, use_password, overwrite, suppress, mnemonic))
        Ok(Wallet::new(None, None, None, None))
    }

    #[pyo3(signature = (n_words=12, use_password=true, overwrite=false, suppress=false))]
    fn create_new_hotkey(
        &self,
        n_words: u8,
        use_password: bool,
        overwrite: bool,
        suppress: bool,
    ) -> PyResult<Self> {
        println!(
            ">>> create_new_hotkey {:?}, {:?}, {:?}, {:?}",
            n_words, use_password, overwrite, suppress
        );

        Ok(Wallet::new(None, None, None, None))
    }

    #[pyo3(signature = (mnemonic, key_type))]
    #[pyo3(text_signature = "(self, mnemonic, key_type)")]
    /// Display the mnemonic and a warning message to keep the mnemonic safe.
    ///
    /// Args:
    ///     keypair (Keypair): Keypair object.
    ///     key_type (str): Type of the key (coldkey or hotkey).
    fn display_mnemonic_msg(&self, mnemonic: String, key_type: &str) {
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
}
