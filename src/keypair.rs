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

use crate::keyfile::{Keyfile, KeyfileType};
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
        let keypair =
            sr25519::Pair::from_seed_slice(seed).expect("Failed to create keypair from seed");
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

    pub fn write_keyfile_data_to_file(
        &self,
        path: &Path,
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

        let keyfile_data = self.to_keyfile_data();
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
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Load and deserialize the keyfile data
        let keyfile_data = Self::get_keypair_from_file(name, key_type)?;
        let keypair = if let Some(pass) = password {
            let decrypted_data = Self::decrypt_keyfile_data(&keyfile_data, pass)?;
            Self::deserialize_from_keyfile_data(&decrypted_data)?
        } else {
            Self::deserialize_from_keyfile_data(&keyfile_data)?
        };

        Ok(keypair)
    }

    pub fn load_keypair(
        name: &str,
        key_type: &str,
        password: Option<&str>,
        mnemonic: Option<&str>,
    ) -> Result<sr25519::Pair, Box<dyn std::error::Error>> {
        // Load and deserialize the keyfile data
        let keypair = Self::load_keypair_dict(name, key_type, password)?;

        // Parse the mnemonic if provided
        let mnemonic = mnemonic
            .ok_or("Mnemonic not provided")?
            .parse::<Mnemonic>()
            .map_err(|e| format!("Failed to parse mnemonic: {}", e))?;

        // Use the first 32 bytes of the mnemonic seed as the seed
        let seed: [u8; 32] = mnemonic.to_seed("").as_slice()[..32]
            .try_into()
            .map_err(|_| "Failed to create seed")?;

        // Create the sr25519 pair from the seed
        let pair = sr25519::Pair::from_seed_slice(&seed)?;
        Ok(pair)
    }

    pub fn get_keypair_from_file(
        name: &str,
        key_type: KeyfileType,
    ) -> Result<Vec<u8>, KeyFileError> {
        let keyfile = Keyfile::new(name, key_type);

        if !keyfile.exists() {
            return Err(KeyFileError::NotFound(
                keyfile.path().to_string_lossy().into_owned(),
            ));
        }

        keyfile.read_bytes().map_err(KeyFileError::Io)
    }

    pub fn create_keypair(mnemonic: Mnemonic, name: &str) -> (sr25519::Pair, [u8; 32]) {
        let seed: [u8; 32] = mnemonic.to_seed("")[..32]
            .try_into()
            .expect("Failed to create seed");

        let derivation_path: Vec<u8> = format!("//{}", name).into_bytes();

        let keypair: sr25519::Pair = Self::derive_sr25519_key(&seed, &derivation_path)
            .expect("Failed to derive sr25519 key");

        (keypair, seed)
    }

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
            let (derived_key, next_chain_code) =
                secret_key.derived_key_simple(chain_code, [*junction]);
            secret_key = derived_key;
            pair = sr25519::Pair::from_seed_slice(&secret_key.to_bytes()[..32])
                .expect("Failed to derive sr25519 key");
            chain_code = next_chain_code;
        }

        Ok(pair)
    }

    pub fn save_keypair(
        key_pair: sr25519::Pair,
        mnemonic: Mnemonic,
        seed: [u8; 32],
        name: &str,
        key_type: KeyfileType,
        password: Option<String>,
    ) -> Self {
        let keypair = Self {
            public_key: Some(key_pair.public().to_vec()),
            ss58_address: Some(key_pair.public().to_ss58check()),
        };
        let path = BT_WALLET_PATH;

        let keyfile = Keyfile::new(
            name.to_string(),
            PathBuf::from(path),
            password.clone(),
            Some(mnemonic.to_string()),
        );

        let key_path = match key_type {
            KeyfileType::HotKey => keyfile.hotkey_file(),
            KeyfileType::ColdKeyPub => keyfile.coldkey_pub_file(),
            KeyfileType::ColdKey => keyfile.coldkey_file(),
        };

        // Ensure the directory exists before writing the file
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).expect("Failed to create directory");
        }

        let password = password.unwrap_or_default();
        if !password.is_empty() {
            let encrypted_data = keypair
                .encrypt_keyfile_data(&password)
                .expect("Failed to encrypt keyfile");
            keypair
                .write_keyfile_data_to_file(&key_path, false)
                .expect("Failed to write encrypted keyfile");
        } else {
            keypair
                .write_keyfile_data_to_file(&key_path, false)
                .expect("Failed to write keyfile");
        }

        keypair
    }

    pub fn create_mnemonic(num_words: u32) -> Result<Mnemonic, Box<dyn std::error::Error>> {
        // Calculate the number of entropy bytes needed based on the number of words
        let entropy_bytes = (num_words / 3) * 4;
        let entropy_size = usize::try_from(entropy_bytes)?;

        // Generate random entropy
        let mut entropy = vec![0u8; entropy_size];
        rand::thread_rng().fill_bytes(&mut entropy);

        // Create a new mnemonic from the generated entropy
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;

        Ok(mnemonic)
    }

    pub fn decrypt_keyfile_data(
        encrypted_data: &[u8],
        password: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
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

    pub fn encrypt_keyfile_data(&self, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let password = password.as_bytes();
        let keyfile_data = self.to_keyfile_data();

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

        // Create the encryption key
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|e| e.to_string())?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        // Generate a random nonce
        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Encrypt the data
        let mut in_out = keyfile_data;
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

    fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
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
    let password_hash = argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| format!("Failed to hash password: {:?}", e))?;
    let key_bytes = password_hash.hash.ok_or("Failed to get hash bytes")?;

    println!("Key derived successfully");

    // Store the derived key securely in a SecretBox
    let secret_key = SecretBox::<[u8; 32]>::new(|key| {
        key.copy_from_slice(&key_bytes.as_bytes()[..32]);
    });

    // Extract nonce from ciphertext
    let nonce_bytes: [u8; NONCE_LEN] = ciphertext
        .get(..NONCE_LEN)
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
    let tag_start = ciphertext
        .len()
        .checked_sub(AES_256_GCM.tag_len())
        .ok_or("Ciphertext too short for tag")?;
    let mut in_out = ciphertext
        .get(NONCE_LEN..tag_start)
        .ok_or("Invalid ciphertext length")?
        .to_vec();
    let tag = ciphertext
        .get(tag_start..)
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
        }
        Err(e) => {
            println!("Decryption failed with error: {:?}", e);
            Err(format!("Decryption failed: {:?}", e).into())
        }
    }
}

pub fn secret_box_encrypt_decrypt_demo(
    password: &str,
    plaintext: &str,
) -> Result<(), Box<dyn Error>> {
    println!("Original plaintext: {}", plaintext);

    // Encrypt the plaintext
    let (ciphertext, salt) = secret_box_encrypt_demo(password, plaintext.as_bytes())?;
    println!(
        "Encrypted ciphertext (base64): {}",
        base64::encode(&ciphertext)
    );
    println!("Salt (base64): {}", salt.as_str());

    // Decrypt the ciphertext
    let decrypted = secret_box_decrypt_demo(password, &ciphertext, &salt)?;
    let decrypted_text = String::from_utf8(decrypted)?;
    println!("Decrypted text: {}", decrypted_text);

    // Verify that the decrypted text matches the original plaintext
    assert_eq!(
        plaintext, decrypted_text,
        "Decrypted text does not match original plaintext"
    );
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
