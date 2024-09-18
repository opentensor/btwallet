use serde::{Deserialize, Serialize};

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