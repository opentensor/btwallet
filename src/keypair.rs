use crate::wallet::BT_WALLET_PATH;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use bip39::{Language, Mnemonic};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
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

use base64;
use secrets::{SecretBox, SecretVec};
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
    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),
}
#[derive(Debug)]
pub struct Keypair {
    pub public_key: Option<Vec<u8>>,
    pub ss58_address: Option<String>,
}

impl Keypair {

    pub fn from_mnemonic(&self, mnemonic: &str) -> sr25519::Pair {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .expect("Failed to parse mnemonic");
        let seed = mnemonic.to_seed("");
        let keypair = sr25519::Pair::from_seed_slice(&seed[..32])
            .expect("Failed to create keypair from seed");
        keypair
    }
    pub fn from_seed(&self, seed: &[u8]) -> sr25519::Pair {
        let keypair = sr25519::Pair::from_seed_slice(seed)
            .expect("Failed to create keypair from seed");
        keypair
    }

    pub fn to_keyfile_data(&self) -> Vec<u8> {
        let json_data = json!({
            "accountId": self.public_key.as_ref().map(|pk| format!("{}", hex::encode(pk))),
            "publicKey": self.public_key.as_ref().map(|pk| format!("{}", hex::encode(pk))),
            "ss58Address": self.ss58_address.clone(),
        });

        serde_json::to_vec(&json_data).unwrap()
    }

    pub fn deserialize_from_keyfile_data(keyfile_data: &[u8]) -> Result<Self, serde_json::Error> {
        let json_data: serde_json::Value = serde_json::from_slice(keyfile_data)?;

        Ok(Self {
            public_key: json_data["publicKey"]
                .as_str()
                .and_then(|s| hex::decode(s).ok()),

            ss58_address: json_data["ss58Address"].as_str().map(String::from),
        })
    }
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

pub fn load_keypair_dict(
    name: &str,
    key_type: &str,
    password: Option<&str>,
) -> Result<Keypair, Box<dyn std::error::Error>> {
    // Load and deserialize the keyfile data
    let keyfile_data = get_keypair_from_file(name, key_type)?;
    let keypair = if let Some(pass) = password {
        let decrypted_data = decrypt_keyfile_data(&keyfile_data, pass)?;
        Keypair::deserialize_from_keyfile_data(&decrypted_data)?
    } else {
        Keypair::deserialize_from_keyfile_data(&keyfile_data)?
    };

    Ok(keypair)
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
pub fn load_keypair(
    name: &str,
    key_type: &str,
    password: Option<&str>,
    mnemonic: Option<&str>,
) -> Result<sr25519::Pair, Box<dyn std::error::Error>> {
    // Load and deserialize the keyfile data
    let keypair = load_keypair_dict(name, key_type, password)?;

    // Extract the private key
    // let private_key = keypair
    //     .private_key
    //     .ok_or("Private key not found in keyfile data")?;

    // Convert the private key to a hex string and then decode it
    // let private_key_hex = hex::encode(&private_key);
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &mnemonic.unwrap())
        .expect("Failed to parse mnemonic");
    // Use the first 32 bytes of the private key as the seed
    let seed: [u8; 32] = mnemonic.to_seed("")
        .as_slice()[..32]
        .try_into()
        .expect("Failed to create seed");

    // Final validation of the seed length
    if seed.len() != 32 {
        return Err("Invalid seed length".into());
    }

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
pub fn get_keypair_from_file(name: &str, key_type: &str) -> Result<Vec<u8>, KeyFileError> {
    let default_path = BT_WALLET_PATH;
    let path = match key_type {
        "hotkey" => hotkey_file(default_path, name),
        "coldkeypub" => coldkey_pub_file(default_path, name),
        "coldkey" => coldkey_file(default_path, name),
        _ => return Err(KeyFileError::InvalidKeyType(key_type.to_string())),
    };

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
    key_type: &str,
    password: Option<String>,
) -> Keypair {
    let keypair = Keypair {
        public_key: Some(key_pair.public().to_vec()),
        ss58_address: Some(key_pair.public().to_ss58check()),
    };
    let path = BT_WALLET_PATH;
    let key_path;
    if key_type == "hotkey" {
        key_path = hotkey_file(path, name);
    } else if key_type == "coldkeypub" {
        key_path = coldkey_pub_file(path, name);
    } else if key_type == "coldkey" {
        key_path = coldkey_file(path, name);
    } else {
        panic!("Invalid key type: {}", key_type);
    }
    // Ensure the directory exists before writing the file
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create directory");
    }
    let password = password.unwrap_or_else(|| "".to_string());
    if !password.is_empty() {
        let encrypted_data =
            encrypt_keyfile_data(keypair.to_keyfile_data(), &password)
                .expect("Failed to encrypt keyfile");
        write_keyfile_data_to_file(&key_path, encrypted_data, false)
            .expect("Failed to write encrypted keyfile");
    } else {
        write_keyfile_data_to_file(
            &key_path,
            keypair.to_keyfile_data(),
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
pub fn create_keypair(mnemonic: Mnemonic, name: &str) -> (sr25519::Pair, [u8; 32]) {
    let seed: [u8; 32] = mnemonic.to_seed("")[..32]
        .try_into()
        .expect("Failed to create seed");

    let derivation_path: Vec<u8> = format!("//{}", name).into_bytes();

    let keypair: sr25519::Pair =
        derive_sr25519_key(&seed, &derivation_path).expect("Failed to derive sr25519 key");

    (keypair, seed)
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
    let salt = SaltString::encode_b64(NACL_SALT)?;

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
    let salt = SaltString::encode_b64(NACL_SALT)?;

    // Hash the password to derive the key
    let password_hash = argon2.hash_password(password, &salt)?;
    let hash = password_hash.hash.ok_or("Failed to generate hash")?;
    let key = hash.as_bytes(); // gus go here
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

// The purpose of SecretBox from the secrets crate is primarily for secure memory management of sensitive data, not for encryption and decryption operations as we might assume from its name. Let's break down its main features and use cases:

// Secure Memory Allocation:
// SecretBox allocates memory in a way that tries to prevent the secret data from being written to disk (e.g., in swap files or core dumps).
// Memory Protection:
// It uses operating system features (like mprotect on Unix systems) to protect the memory pages containing the secret data. This can help prevent other processes from reading this memory.
// Zeroing Memory:
// When the SecretBox is dropped (goes out of scope), it ensures that the memory is overwritten with zeros before being deallocated. This helps prevent secrets from lingering in memory.
// Controlled Access:
// SecretBox provides methods like borrow() and borrow_mut() that give controlled access to the secret data. When these borrows go out of scope, the memory is re-protected.
// Prevention of Accidental Exposure:
// By wrapping secret data in a SecretBox, you make it less likely to accidentally log or print the secret, as it doesn't implement common traits like Debug or Display.


use ring::aead::NONCE_LEN;
use ring::rand::{SecureRandom, SystemRandom};
fn secret_box_encrypt_demo(
    password: &str,
    plaintext: &[u8],
) -> Result<(Vec<u8>, SaltString), Box<dyn Error>> {
    use ring::aead::BoundKey;
    use ring::aead::SealingKey;
    use ring::aead::AES_256_GCM;

    let salt = SaltString::generate(&mut OsRng);

    // Derive key using Argon2
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    let key_bytes = password_hash.hash.unwrap();

    // Store the derived key securely in a SecretBox
    let secret_key = SecretBox::<[u8; 32]>::new(|key| {
        key.copy_from_slice(&key_bytes.as_bytes()[..32]);
    });

    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|e| format!("Failed to generate nonce: {:?}", e))?;

    // Create an AES-256-GCM SealingKey
    // Step 1: Borrow the secret key from the SecretBox
    let mut sealing_key = {
        let key_bytes = secret_key.borrow();

        // Step 2: Convert the borrowed key to a slice
        let key_slice: &[u8] = key_bytes.as_ref();

        // Step 3: Create an UnboundKey using AES-256-GCM and the key slice
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_slice)
            .map_err(|e| format!("Invalid key: {:?}", e))?;

        // Step 4: Create a SealingKey using the UnboundKey and a OneNonceSequence
        SealingKey::new(unbound_key, OneNonceSequence::new(nonce_bytes))
    };

    // Encrypt the plaintext
    let mut in_out = plaintext.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut in_out)
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    // Combine nonce, ciphertext, and tag
    let mut ciphertext = nonce_bytes.to_vec();
    ciphertext.extend_from_slice(&in_out);
    ciphertext.extend_from_slice(tag.as_ref());

    Ok((ciphertext, salt))
}

fn secret_box_decrypt_demo(
    password: &str,
    ciphertext: &[u8],
    salt: &SaltString,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use ring::aead::{BoundKey, OpeningKey, AES_256_GCM, NONCE_LEN};
    
    println!("Starting decryption process");

    // Derive key using Argon2
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), salt)
        .map_err(|e| format!("Failed to hash password: {:?}", e))?;
    let key_bytes = password_hash.hash.ok_or("Failed to get hash bytes")?;

    println!("Key derived successfully");

    // Store the derived key securely in a SecretBox
    let secret_key = SecretBox::<[u8; 32]>::new(|key| {
        key.copy_from_slice(&key_bytes.as_bytes()[..32]);
    });

    // Extract nonce from ciphertext
    let nonce_bytes: [u8; NONCE_LEN] = ciphertext.get(..NONCE_LEN)
        .ok_or("Ciphertext too short for nonce")?
        .try_into()
        .map_err(|_| "Failed to extract nonce")?;

    println!("Nonce extracted successfully");

    // Create an AES-256-GCM OpeningKey
    let mut opening_key = {
        let key_bytes = secret_key.borrow();
        let key_slice: &[u8] = key_bytes.as_ref();
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_slice)
            .map_err(|e| format!("Invalid key: {:?}", e))?;
        OpeningKey::new(unbound_key, OneNonceSequence::new(nonce_bytes))
    };

    println!("OpeningKey created successfully");

    // Separate ciphertext and tag
    let tag_start = ciphertext.len().checked_sub(AES_256_GCM.tag_len())
        .ok_or("Ciphertext too short for tag")?;
    let mut in_out = ciphertext.get(NONCE_LEN..tag_start)
        .ok_or("Invalid ciphertext length")?
        .to_vec();
    let tag = ciphertext.get(tag_start..)
        .ok_or("Failed to extract tag")?
        .to_vec();

    println!("Ciphertext and tag separated successfully");
    println!("in_out length: {}", in_out.len());
    println!("tag length: {}", tag.len());

    // Decrypt the ciphertext
    match opening_key.open_in_place(Aad::empty(), &mut in_out) {
        Ok(_) => {
            println!("Decryption successful");
            println!("Decrypted data: {:?}", in_out);
            Ok(in_out)
        },
        Err(e) => {
            println!("Decryption failed with error: {:?}", e);
            Err(format!("Decryption failed: {:?}", e).into())
        }
    }
}

pub fn secret_box_encrypt_decrypt_demo(password: &str, plaintext: &str) -> Result<(), Box<dyn Error>> {
    println!("Original plaintext: {}", plaintext);

    // Encrypt the plaintext
    let (ciphertext, salt) = secret_box_encrypt_demo(password, plaintext.as_bytes())?;
    println!("Encrypted ciphertext (base64): {}", base64::encode(&ciphertext));
    println!("Salt (base64): {}", salt.as_str());

    // Decrypt the ciphertext
    let decrypted = secret_box_decrypt_demo(password, &ciphertext, &salt)?;
    let decrypted_text = String::from_utf8(decrypted)?;
    println!("Decrypted text: {}", decrypted_text);

    // Verify that the decrypted text matches the original plaintext
    assert_eq!(plaintext, decrypted_text, "Decrypted text does not match original plaintext");
    println!("Encryption and decryption successful!");

    Ok(())
}

pub fn demo_secret_box() {
    let password = "my_secure_password";
    let plaintext = "This is a secret message";

    match secret_box_encrypt_decrypt_demo(password, plaintext) {
        Ok(_) => println!("Demo completed successfully"),
        Err(e) => eprintln!("Error during demo: {}", e),
    }
}

// Custom NonceSequence implementation for a single use
struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    fn new(nonce: [u8; NONCE_LEN]) -> Self {
        OneNonceSequence(Some(Nonce::assume_unique_for_key(nonce)))
    }
}

impl ring::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}
