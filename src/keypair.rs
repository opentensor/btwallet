use crate::wallet::BT_WALLET_PATH;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use bip39::{Language, Mnemonic};
use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use schnorrkel::{
    derive::{ChainCode, Derivation},
    ExpansionMode, MiniSecretKey,
};
use serde_json::json;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair};
use std::error::Error;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;

const NACL_SALT: &[u8; 16] = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1";
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

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

/// Serializes a Keypair struct into a JSON-formatted byte vector.
///
/// This function takes a reference to a Keypair struct and converts it into a JSON object,
/// which is then serialized into a byte vector. The resulting data is suitable for writing
/// to a keyfile.
///
/// # Arguments
///
/// * `keypair` - A reference to the Keypair struct to be serialized.
///
/// # Returns
///
/// * `Vec<u8>` - A byte vector containing the JSON-formatted keyfile data.
///
/// # Panics
///
/// This function will panic if the JSON serialization fails. In practice, this should not
/// occur unless there's a fundamental issue with the data or the serialization process.
///
/// # Examples
///
/// ```
/// let keypair = Keypair {
///     public_key: Some(vec![1, 2, 3, 4]),
///     private_key: Some(vec![5, 6, 7, 8]),
///     mnemonic: Some("example mnemonic".to_string()),
///     seed_hex: Some(vec![9, 10, 11, 12]),
///     ss58_address: Some("exampleAddress".to_string()),
/// };
/// let keyfile_data = serialized_keypair_to_keyfile_data(&keypair);
/// ```
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

/// Deserializes keyfile data into a Keypair struct.
///
/// This function takes a byte slice containing JSON-formatted keyfile data and
/// attempts to deserialize it into a Keypair struct.
///
/// # Arguments
///
/// * `keyfile_data` - A byte slice containing the JSON-formatted keyfile data.
///
/// # Returns
///
/// * `Result<Keypair, serde_json::Error>` - A Result containing either:
///   - `Ok(Keypair)`: A successfully deserialized Keypair struct.
///   - `Err(serde_json::Error)`: An error if deserialization fails.
///
/// # Examples
///
/// ```
/// let keyfile_data = r#"{"publicKey":"0123...", "privateKey":"abcd...", ...}"#.as_bytes();
/// match deserialize_keyfile_data_to_keypair(keyfile_data) {
///     Ok(keypair) => println!("Deserialized keypair: {:?}", keypair),
///     Err(e) => eprintln!("Failed to deserialize: {}", e),
/// }
/// ```
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

/// Constructs the file path for a hotkey within a wallet.
///
/// This function takes a base path and a name, expands any tilde in the path,
/// and constructs a `PathBuf` representing the location of a hotkey file
/// within the wallet's directory structure.
///
/// # Arguments
///
/// * `path` - A string slice representing the base path of the wallet.
/// * `name` - A string slice representing the name of the wallet and hotkey.
///
/// # Returns
///
/// * `PathBuf` - The constructed path to the hotkey file.
///
/// # Examples
///
/// ```
/// let path = "~/wallets";
/// let name = "my_wallet";
/// let hotkey_path = hotkey_file(path, name);
/// assert_eq!(hotkey_path, PathBuf::from("/home/user/wallets/my_wallet/hotkeys/my_wallet"));
/// ```
fn hotkey_file(path: &str, name: &str) -> PathBuf {
    let wallet_path = PathBuf::from(shellexpand::tilde(path).into_owned()).join(name);
    wallet_path.join("hotkeys").join(name)
}

/// Constructs the file path for a coldkey public key within a wallet.
///
/// This function takes a base path and a name, expands any tilde in the path,
/// and constructs a `PathBuf` representing the location of a coldkey public key file
/// within the wallet's directory structure.
///
/// # Arguments
///
/// * `path` - A string slice representing the base path of the wallet.
/// * `name` - A string slice representing the name of the wallet.
///
/// # Returns
///
/// * `PathBuf` - The constructed path to the coldkey public key file.
///
/// # Examples
///
/// ```
/// let path = "~/wallets";
/// let name = "my_wallet";
/// let coldkeypub_path = coldkey_pub_file(path, name);
/// assert_eq!(coldkeypub_path, PathBuf::from("/home/user/wallets/my_wallet/coldkeypub.txt"));
/// ```
fn coldkey_pub_file(path: &str, name: &str) -> PathBuf {
    let wallet_path = PathBuf::from(shellexpand::tilde(path).into_owned()).join(name);
    wallet_path.join("coldkeypub.txt")
}

/// Writes keyfile data to a file with specific permissions.
///
/// This function writes the provided keyfile data to a file at the specified path.
/// It can optionally overwrite an existing file and sets the file permissions to be
/// readable and writable only by the owner.
///
/// # Arguments
///
/// * `path` - A reference to a `Path` where the keyfile should be written.
/// * `keyfile_data` - A `Vec<u8>` containing the data to be written to the file.
/// * `overwrite` - A boolean flag indicating whether to overwrite an existing file.
///
/// # Returns
///
/// * `Result<(), KeyFileError>` - Ok(()) if the operation is successful, or an error of type `KeyFileError`.
///
/// # Errors
///
/// This function will return an error if:
/// - The file already exists and `overwrite` is set to `false`.
/// - There are issues opening, writing to, or setting permissions on the file.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use your_crate::keypair::write_keyfile_data_to_file;
///
/// let path = Path::new("/path/to/keyfile");
/// let data = vec![1, 2, 3, 4, 5];
/// let result = write_keyfile_data_to_file(path, data, true);
/// ```
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

/// Loads a hotkey pair from a keyfile.
///
/// This function retrieves the private key data from a keyfile, processes it,
/// and creates an sr25519::Pair from the extracted seed.
///
/// # Arguments
///
/// * `hotkey_name` - A string slice that holds the name of the hotkey to load.
///
/// # Returns
///
/// * `Result<sr25519::Pair, Box<dyn std::error::Error>>` - A Result containing the sr25519::Pair if successful,
///   or a boxed error if any step in the process fails.
///
/// # Errors
///
/// This function will return an error if:
/// - The keyfile data cannot be loaded or deserialized.
/// - The private key is missing from the keyfile data.
/// - The decoded private key has an invalid length.
/// - The sr25519::Pair cannot be created from the seed.
pub fn load_hotkey_pair(
    hotkey_name: &str,
    password: Option<&str>,
) -> Result<sr25519::Pair, Box<dyn std::error::Error>> {
    // Load and deserialize the keyfile data
    let keyfile_data = load_keyfile_data_from_file(hotkey_name)?;
    let keypair = if let Some(pass) = password {
        let decrypted_data = decrypt_keyfile_data(&keyfile_data, pass)?;
        deserialize_keyfile_data_to_keypair(&decrypted_data)?
    } else {
        deserialize_keyfile_data_to_keypair(&keyfile_data)?
    };

    // Extract the private key
    let private_key = keypair
        .private_key
        .ok_or("Private key not found in keyfile data")?;

    // Convert the private key to a hex string and then decode it
    let private_key_hex = hex::encode(&private_key);
    let seed = hex::decode(private_key_hex)?;

    // Validate the seed length
    if seed.len() != 64 {
        return Err("Invalid private key length".into());
    }

    // Use the first 32 bytes of the private key as the seed
    let seed = &seed[0..32];

    // Final validation of the seed length
    if seed.len() != 32 {
        return Err("Invalid seed length".into());
    }

    // Create and return the sr25519::Pair
    let pair = sr25519::Pair::from_seed_slice(&seed)?;
    Ok(pair)
}

/// Loads keyfile data from a file with the given name.
///
/// This function attempts to read the contents of a keyfile associated with the provided name.
/// It uses a default path (BT_WALLET_PATH) and constructs the full file path using the `hotkey_file` function.
///
/// # Arguments
///
/// * `name` - A string slice that holds the name of the keyfile to load.
///
/// # Returns
///
/// * `Result<Vec<u8>, KeyFileError>` - A Result containing a vector of bytes with the keyfile data if successful,
///   or a KeyFileError if an error occurs during the process.
///
/// # Errors
///
/// This function will return an error if:
/// - The keyfile does not exist at the expected location.
/// - There are issues opening or reading the file.
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

/// Checks if a file or directory exists at the given path.
///
/// This function is a simple wrapper around the `exists` method of the `Path` struct.
///
/// # Arguments
///
/// * `path` - A reference to a `Path` that represents the file or directory to check.
///
/// # Returns
///
/// * `bool` - Returns `true` if the path exists, `false` otherwise.
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

/// Saves a keypair to a file.
///
/// This function takes a key pair, mnemonic, seed, and other details, creates a `Keypair` struct,
/// and saves it to a file. The file can be optionally encrypted.
///
/// # Arguments
///
/// * `key_pair` - The sr25519 key pair to save.
/// * `mnemonic` - The mnemonic associated with the key pair.
/// * `seed` - The 32-byte seed used to generate the key pair.
/// * `name` - The name to use for the key file.
/// * `encrypt` - Whether to encrypt the key file.
/// * `key_type` - The type of key ("hotkey" or "coldkey").
///
/// # Returns
///
/// Returns a `Keypair` struct containing the saved key information.
///
/// # Panics
///
/// This function will panic if it fails to create directories, encrypt data, or write to the file.
pub fn save_keypair(
    key_pair: sr25519::Pair,
    mnemonic: Mnemonic,
    seed: [u8; 32],
    name: &str,
    encrypt: bool,
    key_type: &str,
) -> Keypair {
    let keypair = Keypair {
        public_key: Some(key_pair.public().to_vec()),
        private_key: Some(key_pair.to_raw_vec()),
        mnemonic: Some(mnemonic.to_string()),
        seed_hex: Some(seed.to_vec()),
        ss58_address: Some(key_pair.public().to_ss58check()),
    };
    let path = BT_WALLET_PATH;
    let key_path;
    if key_type == "hotkey" {
        key_path = hotkey_file(path, name);
    } else {
        key_path = coldkey_pub_file(path, name);
    }
    // Ensure the directory exists before writing the file
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create directory");
    }
    let password = "ben+is+a+css+pro";
    if encrypt {
        let encrypted_data =
            encrypt_keyfile_data(serialized_keypair_to_keyfile_data(&keypair), password)
                .expect("Failed to encrypt keyfile");
        write_keyfile_data_to_file(&key_path, encrypted_data, false)
            .expect("Failed to write encrypted keyfile");
    } else {
        write_keyfile_data_to_file(
            &key_path,
            serialized_keypair_to_keyfile_data(&keypair),
            false,
        )
        .expect("Failed to write keyfile");
    }
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

/// Creates a new coldkey pair and returns it along with its seed.
///
/// This function performs the following steps:
/// 1. Generates a seed from the provided mnemonic.
/// 2. Creates a derivation path using the provided name.
/// 3. Derives an sr25519 key pair using the seed and derivation path.
///
/// # Arguments
///
/// * `mnemonic` - A `Mnemonic` object representing the seed phrase.
/// * `name` - A string slice containing the name for the coldkey.
///
/// # Returns
///
/// Returns a tuple containing:
/// - An `sr25519::Pair` representing the generated coldkey pair.
/// - A 32-byte array containing the seed used to generate the key pair.
///
/// # Panics
///
/// This function will panic if:
/// - It fails to create a seed from the mnemonic.
/// - It fails to derive the sr25519 key.
pub fn create_coldkey(mnemonic: Mnemonic, name: &str) -> (sr25519::Pair, [u8; 32]) {
    let seed: [u8; 32] = mnemonic.to_seed("")[..32]
        .try_into()
        .expect("Failed to create seed");

    let derivation_path: Vec<u8> = format!("//{}", name).into_bytes();

    let coldkey_pair: sr25519::Pair =
        derive_sr25519_key(&seed, &derivation_path).expect("Failed to derive sr25519 key");

    (coldkey_pair, seed)
}

fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
/// Decrypts the given encrypted keyfile data using the provided password.
///
/// This function performs the following steps:
/// 1. Derives a decryption key from the password using Argon2 and a constant salt.
/// 2. Creates a ChaCha20-Poly1305 decryption key.
/// 3. Extracts the nonce from the encrypted data.
/// 4. Decrypts the data using the derived key and extracted nonce.
///
/// # Arguments
///
/// * `encrypted_data` - A byte slice containing the encrypted keyfile data.
/// * `password` - A string slice containing the password used for decryption.
///
/// # Returns
///
/// Returns a `Result` which is:
/// - `Ok(Vec<u8>)` containing the decrypted data if successful.
/// - `Err(Box<dyn Error>)` if any error occurs during the decryption process.
///
/// # Errors
///
/// This function may return an error if:
/// - The password hashing process fails.
/// - The key derivation process fails.
/// - The encrypted data is of invalid length or format.
/// - The decryption process fails.
fn decrypt_keyfile_data(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let password = password.as_bytes();

    // Create Argon2 instance
    let argon2 = Argon2::default();

    // Create a SaltString from our constant salt
    let salt = SaltString::b64_encode(NACL_SALT)?;

    // Hash the password to derive the key
    let password_hash = argon2.hash_password(password, &salt)?;
    let hash = password_hash.hash.ok_or("Failed to generate hash")?;
    let key = hash.as_bytes();

    // Ensure the key is the correct length
    if key.len() != KEY_SIZE {
        return Err("Invalid key length".into());
    }

    // Create the decryption key
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|e| e.to_string())?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    // Extract the nonce and encrypted data
    if encrypted_data.len() < 5 + NONCE_SIZE {
        return Err("Invalid encrypted data length".into());
    }
    let nonce_bytes = &encrypted_data[5..5 + NONCE_SIZE];
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|e| e.to_string())?;
    let ciphertext = &encrypted_data[5 + NONCE_SIZE..];

    // Decrypt the data
    let mut in_out = ciphertext.to_vec();
    less_safe_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| e.to_string())?;

    // Remove the authentication tag
    in_out.truncate(in_out.len() - CHACHA20_POLY1305.tag_len());

    Ok(in_out)
}

/// Encrypts the given keyfile data using the provided password.
///
/// This function performs the following steps:
/// 1. Derives an encryption key from the password using Argon2 and a constant salt.
/// 2. Creates a ChaCha20-Poly1305 encryption key.
/// 3. Generates a random nonce.
/// 4. Encrypts the keyfile data using the derived key and nonce.
/// 5. Combines the encrypted data with a "$NACL" prefix and the nonce.
///
/// # Arguments
///
/// * `keyfile_data` - A vector of bytes containing the keyfile data to be encrypted.
/// * `password` - A string slice containing the password used for encryption.
///
/// # Returns
///
/// Returns a `Result` which is:
/// - `Ok(Vec<u8>)` containing the encrypted data if successful.
/// - `Err(Box<dyn Error>)` if any error occurs during the encryption process.
///
/// # Errors
///
/// This function may return an error if:
/// - The password hashing process fails.
/// - The encryption key creation fails.
/// - The encryption process itself fails.
fn encrypt_keyfile_data(keyfile_data: Vec<u8>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let password = password.as_bytes();

    // Create Argon2 instance
    let argon2 = Argon2::default();

    // Create a SaltString from our constant salt
    let salt = SaltString::b64_encode(NACL_SALT)?;

    // Hash the password to derive the key
    let password_hash = argon2.hash_password(password, &salt)?;
    let hash = password_hash.hash.ok_or("Failed to generate hash")?;
    let key = hash.as_bytes();
    // Ensure the key is the correct length
    if key.len() != KEY_SIZE {
        return Err("Invalid key length".into());
    }

    // Create the encryption key
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|e| e.to_string())?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    // Generate a random nonce
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt the data
    let mut in_out = keyfile_data.to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| e.to_string())?;

    // Combine the nonce, encrypted data with the "$NACL" prefix
    let mut result = Vec::with_capacity(5 + NONCE_SIZE + in_out.len());
    result.extend_from_slice(b"$NACL");
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&in_out);

    Ok(result)
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
