use crate::wallet::BT_WALLET_PATH;
use bip39::{Language, Mnemonic};
use rand::RngCore;
use schnorrkel::{
    derive::{ChainCode, Derivation},
    ExpansionMode, MiniSecretKey,
};
use serde_json::json;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyFileError {
    #[error("Keyfile at: {0} is not writable")]
    NotWritable(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Keyfile at: {0} not found")]
    NotFound(String),
}
#[derive(Debug)]
pub struct Keypair {
    pub public_key: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
    pub mnemonic: Option<String>,
    pub seed_hex: Option<Vec<u8>>,
    pub ss58_address: Option<String>,
}

fn serialized_keypair_to_keyfile_data(keypair: &Keypair) -> Vec<u8> {
    let json_data = json!({
        "accountId": keypair.public_key.as_ref().map(|pk| format!("{}", hex::encode(pk))),
        "publicKey": keypair.public_key.as_ref().map(|pk| format!("{}", hex::encode(pk))),
        "privateKey": keypair.private_key.as_ref().map(|pk| format!("{}", hex::encode(pk))),
        "secretPhrase": keypair.mnemonic.clone(),
        "secretSeed": keypair.seed_hex.as_ref().map(|seed| format!("{}", hex::encode(seed))),
        "ss58Address": keypair.ss58_address.clone(),
    });

    serde_json::to_vec(&json_data).unwrap()
}

pub fn deserialize_keyfile_data_to_keypair(
    keyfile_data: &[u8],
) -> Result<Keypair, serde_json::Error> {
    let json_data: serde_json::Value = serde_json::from_slice(keyfile_data)?;

    Ok(Keypair {
        public_key: json_data["publicKey"]
            .as_str()
            .and_then(|s| hex::decode(s).ok()),
        private_key: json_data["privateKey"]
            .as_str()
            .and_then(|s| hex::decode(s).ok()),
        mnemonic: json_data["secretPhrase"].as_str().map(String::from),
        seed_hex: json_data["secretSeed"]
            .as_str()
            .and_then(|s| hex::decode(s).ok()),
        ss58_address: json_data["ss58Address"].as_str().map(String::from),
    })
}

fn hotkey_file(path: &str, name: &str) -> PathBuf {
    let wallet_path = PathBuf::from(shellexpand::tilde(path).into_owned()).join(name);
    wallet_path.join("hotkeys").join(name)
}

pub fn write_keyfile_data_to_file(
    path: &Path,
    keyfile_data: Vec<u8>,
    overwrite: bool,
) -> Result<(), KeyFileError> {
    if exists_on_device(path) && !overwrite {
        return Err(KeyFileError::NotWritable(
            path.to_string_lossy().into_owned(),
        ));
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    file.write_all(&keyfile_data)?;

    // Set file permissions
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o600); // This is equivalent to stat.S_IRUSR | stat.S_IWUSR
    file.set_permissions(perms)?;

    Ok(())
}

pub fn load_hotkey_pair(hotkey_name: &str) -> Result<sr25519::Pair, Box<dyn std::error::Error>> {
    let keyfile_data = load_keyfile_data_from_file(hotkey_name)?;
    let keypair = deserialize_keyfile_data_to_keypair(&keyfile_data)?;
    // println!("keypair: {:?}", keypair);
    let private_key = keypair
        .private_key
        .ok_or("Private key not found in keyfile data")?;

    // Convert the private key Vec<u8> to a hex string
    let private_key_hex = hex::encode(&private_key);
    // println!("Private key hex: {}", private_key_hex);

    // Decode the hex string to bytes
    let seed = hex::decode(private_key_hex)?;

    // The private key is 64 bytes (128 hex characters), but we need a 32-byte seed
    if seed.len() != 64 {
        return Err("Invalid private key length".into());
    }

    // Take only the first 32 bytes of the private key as the seed
    let seed = &seed[0..32];

    if seed.len() != 32 {
        return Err("Invalid seed length".into());
    }

    let pair = sr25519::Pair::from_seed_slice(&seed)?;
    Ok(pair)
}

// let seed = hex::decode(private_key)?;

// // if seed.len() != 32 {
// //     return Err("Invalid seed length".into());
// // }

// let pair = sr25519::Pair::from_seed_slice(&seed)
//     .map_err(|_| "Failed to create pair from seed")?;

// Ok(pair)
// }

pub fn load_keyfile_data_from_file(name: &str) -> Result<Vec<u8>, KeyFileError> {
    let default_path = BT_WALLET_PATH;
    let path = hotkey_file(default_path, name);

    if !exists_on_device(&path) {
        return Err(KeyFileError::NotFound(path.to_string_lossy().into_owned()));
    }

    let mut file = File::open(path)?;
    let mut keyfile_data = Vec::new();
    file.read_to_end(&mut keyfile_data)?;

    Ok(keyfile_data)
}

fn exists_on_device(path: &Path) -> bool {
    path.exists()
}

/// Creates a new mnemonic phrase with the specified number of words.
///
/// This function generates a random mnemonic phrase using the BIP39 standard.
/// The number of words in the mnemonic is determined by the `num_words` parameter.
///
/// # Arguments
///
/// * `num_words` - The number of words in the mnemonic phrase. Valid values are typically 12, 15, 18, 21, or 24.
///
/// # Returns
///
/// * `Result<Mnemonic, &'static str>` - A Result containing the generated Mnemonic if successful, or an error message if the operation fails.
///
/// # Examples
///
/// ```
/// let mnemonic = create_mnemonic(12).expect("Failed to create mnemonic");
/// println!("Generated mnemonic: {}", mnemonic.to_string());
/// ```
///
/// # Errors
///
/// This function will return an error if:
/// - The entropy generation fails
/// - The mnemonic creation from the generated entropy fails
pub fn create_mnemonic(num_words: u32) -> Result<Mnemonic, &'static str> {
    // Calculate the number of entropy bytes needed based on the number of words
    let entropy_bytes = (num_words / 3) * 4;
    let entropy_size = usize::try_from(entropy_bytes);

    // Generate random entropy
    let mut entropy = vec![0u8; entropy_size.unwrap_or(0)];
    rand::thread_rng().fill_bytes(&mut entropy);

    // Create a new mnemonic from the generated entropy
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|_| "Failed to create mnemonic")?;

    Ok(mnemonic)
}

/// Derives an sr25519 key pair from a seed and a derivation path.
///
/// This function takes a seed and a derivation path to generate an sr25519 key pair.
/// It uses the Schnorrkel/Ristretto x25519 ("sr25519") signature system.
///
/// # Arguments
///
/// * `seed` - A byte slice containing the seed for key generation. Must be exactly 32 bytes long.
/// * `path` - A byte slice representing the derivation path for the key.
///
/// # Returns
///
/// * `Result<sr25519::Pair, String>` - A Result containing the derived sr25519 key pair if successful,
///   or an error message as a String if the operation fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The seed length is not exactly 32 bytes.
/// - Any of the key derivation steps fail.
///
/// # Example
///
/// ```
/// let seed = [0u8; 32]; // Replace with actual seed
/// let path = b"//some/path";
/// let key_pair = derive_sr25519_key(&seed, path).expect("Key derivation failed");
/// ```
fn derive_sr25519_key(seed: &[u8], path: &[u8]) -> Result<sr25519::Pair, String> {
    // Ensure the seed is the correct length
    let seed_len = seed.len();
    if seed_len != 32 {
        return Err(format!(
            "Invalid seed length: expected 32, got {}",
            seed_len
        ));
    }

    // Create the initial mini secret key from the seed
    let mini_secret_key =
        MiniSecretKey::from_bytes(seed).expect("Failed to create mini secret key");

    // Convert to a secret key and derive the initial key pair
    let mut secret_key = mini_secret_key.expand(ExpansionMode::Ed25519);
    let mut pair = sr25519::Pair::from_seed_slice(&secret_key.to_bytes()[..32])
        .expect("Failed to derive sr25519 key");

    // Initialize the chain code
    let mut chain_code = ChainCode(seed.try_into().expect("Failed to create seed"));

    // Iteratively derive the key pair using the path
    for junction in path {
        let (derived_key, next_chain_code) = secret_key.derived_key_simple(chain_code, [*junction]);
        secret_key = derived_key;
        pair = sr25519::Pair::from_seed_slice(&secret_key.to_bytes()[..32])
            .expect("Failed to derive sr25519 key");
        chain_code = next_chain_code;
    }

    Ok(pair)
}

pub fn save_keypair(
    hotkey_pair: sr25519::Pair,
    mnemonic: Mnemonic,
    seed: [u8; 32],
    name: &str,
) -> Keypair {
    let keypair = Keypair {
        public_key: Some(hotkey_pair.public().to_vec()),
        private_key: Some(hotkey_pair.to_raw_vec()),
        mnemonic: Some(mnemonic.to_string()),
        seed_hex: Some(seed.to_vec()),
        ss58_address: Some(hotkey_pair.public().to_ss58check()),
    };
    let path = BT_WALLET_PATH;
    let hotkey_path = hotkey_file(path, name);
    // Ensure the directory exists before writing the file
    if let Some(parent) = hotkey_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create directory");
    }
    write_keyfile_data_to_file(
        &hotkey_path,
        serialized_keypair_to_keyfile_data(&keypair),
        false,
    )
    .expect("Failed to write keyfile");
    keypair
}

/// Creates a new hotkey pair and writes it to a file.
///
/// This function performs the following steps:
/// 1. Generates a seed from the provided mnemonic.
/// 2. Creates a derivation path using the provided name.
/// 3. Derives an sr25519 key pair using the seed and derivation path.
/// 4. Creates a `Keypair` struct with the derived key information.
/// 5. Writes the keypair data to a file in the wallet directory.
///
/// # Arguments
///
/// * `mnemonic` - A `Mnemonic` object representing the seed phrase.
/// * `name` - A string slice containing the name for the hotkey.
///
/// # Returns
///
/// Returns a `Keypair` struct containing the generated key information.
///
/// # Panics
///
/// This function will panic if:
/// - It fails to create a seed from the mnemonic.
/// - It fails to derive the sr25519 key.
/// - It fails to create the directory for the keyfile.
/// - It fails to write the keyfile.
pub fn create_hotkey(mnemonic: Mnemonic, name: &str) -> (sr25519::Pair, [u8; 32]) {
    let seed: [u8; 32] = mnemonic.to_seed("")[..32]
        .try_into()
        .expect("Failed to create seed");

    let derivation_path: Vec<u8> = format!("//{}", name).into_bytes();

    let hotkey_pair: sr25519::Pair =
        derive_sr25519_key(&seed, &derivation_path).expect("Failed to derive sr25519 key");

    (hotkey_pair, seed) //hack to demo hotkey_pair sign
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Language;
    use rand::Rng;

    #[test]
    fn test_create_mnemonic_valid_word_counts() {
        let valid_word_counts = [12, 15, 18, 21, 24];
        for &word_count in &valid_word_counts {
            let result = create_mnemonic(word_count);
            assert!(
                result.is_ok(),
                "Failed to create mnemonic with {} words",
                word_count
            );
            let mnemonic = result.unwrap();
            assert_eq!(
                mnemonic.word_count(),
                word_count as usize,
                "Mnemonic word count doesn't match expected"
            );
        }
    }

    #[test]
    fn test_mnemonic_uniqueness() {
        let mnemonic1 = create_mnemonic(12).unwrap();
        let mnemonic2 = create_mnemonic(12).unwrap();
        assert_ne!(
            mnemonic1.to_string(),
            mnemonic2.to_string(),
            "Two generated mnemonics should not be identical"
        );
    }

    #[test]
    fn test_mnemonic_language() {
        let mnemonic = create_mnemonic(12).unwrap();
        assert_eq!(
            mnemonic.language(),
            Language::English,
            "Mnemonic should be in English"
        );
    }

    #[test]
    fn test_derive_sr25519_key_valid_input() {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rng.gen();
        let path = b"/some/path";

        let result = derive_sr25519_key(&seed, path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_sr25519_key_invalid_seed_length() {
        let seed = [0u8; 16]; // Invalid length
        let path = b"/some/path";

        let result = derive_sr25519_key(&seed, path);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err
            .to_string()
            .contains("Invalid seed length: expected 32, got 16"));
    }

    #[test]
    fn test_derive_sr25519_key_empty_path() {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rng.gen();
        let path = b"";

        let result = derive_sr25519_key(&seed, path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_sr25519_key_deterministic() {
        let seed: [u8; 32] = [42u8; 32];
        let path = b"/test/path";

        let result1 = derive_sr25519_key(&seed, path);
        let result2 = derive_sr25519_key(&seed, path);

        assert!(result1.is_ok() && result2.is_ok());
        assert_eq!(
            result1.unwrap().public(),
            result2.unwrap().public(),
            "Derived keys should be identical for the same seed and path"
        );
    }
}
