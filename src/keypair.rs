use pyo3::prelude::*;

use pyo3::exceptions::PyValueError;

use bip39::{Mnemonic, MnemonicType, Language };
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use primitive_types::U256;

use crate::sr25519::*;


use crate::scalecodec::*;


#[pyclass]
pub struct Keypair {
    #[pyo3(get, set)]
    crypto_type: u8,
    #[pyo3(get, set)]
    seed_hex: Option<String>,
    #[pyo3(get, set)]
    derive_path: Option<String>,
    #[pyo3(get, set)]
    ss58_format: Option<u16>,
    #[pyo3(get, set)]
    public_key: Vec<u8>,
    #[pyo3(get, set)]
    ss58_address: Option<String>,
    #[pyo3(get, set)]
    private_key: Vec<u8>,
    #[pyo3(get, set)]
    mnemonic: Option<String>,
}


fn parse_derivation_path(str_derivation_path: &str) -> PyResult<Vec<u32>> {
    if !str_derivation_path.starts_with("m/") {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Can't recognize derivation path. It should look like \"m/44'/60/0'/0\"."
        ));
    }

    let mut path = Vec::new();
    for component in str_derivation_path.trim_start_matches("m/").split('/') {
        if component.ends_with('\'') {
            let value = component.trim_end_matches('\'').parse::<u32>()?;
            path.push(0x80000000 + value); // BIP32_PRIVDEV + int(i[:-1])
        } else {
            path.push(component.parse::<u32>()?);
        }
    }

    Ok(path)
}


fn bip39seed_to_bip32masternode(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    const BIP32_SEED_MODIFIER: &[u8] = b"Bitcoin seed";

    let mut mac = Hmac::<Sha512>::new_from_slice(BIP32_SEED_MODIFIER)
        .expect("HMAC can take key of any size");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let (key, chain_code) = result.split_at(32);
    (key.try_into().unwrap(), chain_code.try_into().unwrap())
}

/// Derives a BIP32 child key from a parent key and chain code.
///
/// This function implements the BIP32 key derivation algorithm to generate a child key
/// from a parent key and chain code. It supports both normal and hardened derivation.
///
/// # Arguments
///
/// * `parent_key` - A reference to a 32-byte array containing the parent private key.
/// * `parent_chain_code` - A reference to a 32-byte array containing the parent chain code.
/// * `i` - A 32-bit unsigned integer representing the child index. If the most significant bit
///         is set (i >= 2^31), it performs hardened derivation.
///
/// # Returns
///
/// A tuple containing two 32-byte arrays:
/// * The first array is the derived child private key.
/// * The second array is the derived child chain code.
///
/// # Panics
///
/// This function will panic if:
/// * The length of `parent_key` or `parent_chain_code` is not 32 bytes.
/// * The HMAC-SHA512 initialization fails (which should never happen with a 32-byte key).
///
/// # Examples
///
/// ```
/// let parent_key = [0u8; 32];
/// let parent_chain_code = [0u8; 32];
/// let child_index = 0;
/// let (child_key, child_chain_code) = derive_bip32childkey(&parent_key, &parent_chain_code, child_index);
/// ```
///
/// # Note
///
/// This function uses a loop to handle the edge case where the derived key is invalid.
/// In practice, this is extremely unlikely to occur, but the loop ensures compliance with the BIP32 specification.
fn derive_bip32childkey(parent_key: &[u8; 32], parent_chain_code: &[u8; 32], i: u32) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use secp256k1::{PublicKey, Secp256k1};

    assert_eq!(parent_key.len(), 32);
    assert_eq!(parent_chain_code.len(), 32);

    let k = parent_chain_code;
    let key = if (i & 0x80000000) != 0 {
        let mut key = [0u8; 33];
        key[1..].copy_from_slice(parent_key);
        key
    } else {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secp256k1::SecretKey::from_slice(parent_key).unwrap());
        public_key.serialize()
    };

    let mut d = Vec::with_capacity(key.len() + 4);
    d.extend_from_slice(&key);
    d.extend_from_slice(&i.to_be_bytes());

    loop {
        let mut mac = Hmac::<Sha512>::new_from_slice(k).expect("HMAC can take key of any size");
        mac.update(&d);
        let h = mac.finalize().into_bytes();

        let (key, chain_code) = h.split_at(32);
        let a = U256::from_big_endian(key);
        let b = U256::from_big_endian(parent_key);
        let key = (a + b) % U256::from(secp256k1::constants::CURVE_ORDER);

        if a < U256::from(secp256k1::constants::CURVE_ORDER) && key != U256::zero() {
            let mut key_bytes = [0u8; 32];
            key.to_big_endian(&mut key_bytes);
            return (key_bytes, chain_code.try_into().unwrap());
        }

        d = vec![0x01];
        d.extend_from_slice(&h[32..]);
        d.extend_from_slice(&i.to_be_bytes());
    }
}


/// Converts a mnemonic phrase to a BIP39 seed.
///
/// This function takes a mnemonic phrase and an optional passphrase to generate
/// a 64-byte BIP39 seed using PBKDF2 with HMAC-SHA512.
///
/// # Arguments
///
/// * `mnemonic` - A string slice containing the mnemonic phrase.
/// * `passphrase` - A string slice containing an optional passphrase for additional security.
///
/// # Returns
///
/// A 64-byte array containing the generated BIP39 seed.
///
/// # Examples
///
/// ```
/// let mnemonic = "toward also shift move pet nuclear strike book outdoor pilot afford allow";
/// let passphrase = "some password";
/// let seed = mnemonic_to_bip39seed(mnemonic, passphrase);
/// assert_eq!(seed.len(), 64);
/// ```
fn mnemonic_to_bip39seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    const BIP39_SALT_MODIFIER: &str = "mnemonic";
    const BIP39_PBKDF2_ROUNDS: u32 = 2048;

    let mnemonic = mnemonic.as_bytes();
    let salt = format!("{}{}", BIP39_SALT_MODIFIER, passphrase);

    let mut seed = [0u8; 64];
    pbkdf2::<Hmac<Sha512>>(mnemonic, salt.as_bytes(), BIP39_PBKDF2_ROUNDS, &mut seed);
    
    seed
}

/// Converts a BIP39 mnemonic phrase to a mini secret key.
///
/// This function takes a BIP39 mnemonic phrase, a password, and an optional language code,
/// and generates a 32-byte mini secret key.
///
/// # Arguments
///
/// * `phrase` - A string slice containing the BIP39 mnemonic phrase.
/// * `password` - A string slice containing the password (can be empty).
/// * `language_code` - An optional string slice specifying the language code of the mnemonic.
///                     Defaults to "en" (English) if not provided.
///
/// # Returns
///
/// Returns a `PyResult<Vec<u8>>` containing the 32-byte mini secret key.
///
/// # Errors
///
/// This function will return an error if:
/// * An invalid language code is provided.
/// * The mnemonic phrase is invalid.
///
/// # Examples
///
/// ```
/// let phrase = "toward also shift move pet nuclear strike book outdoor pilot afford allow";
/// let password = "";
/// let mini_secret = bip39_to_mini_secret(phrase, password, None).unwrap();
/// assert_eq!(mini_secret.len(), 32);
/// ```
pub fn bip39_to_mini_secret(phrase: &str, password: &str, language_code: Option<&str>) -> PyResult<Vec<u8>> {
	let salt = format!("mnemonic{}", password);

	let language = match Language::from_language_code(language_code.unwrap_or("en")) {
		Some(language) => language,
		None => return Err(PyValueError::new_err("Invalid language_code"))
	};

	let mnemonic = match Mnemonic::from_phrase(phrase, language) {
		Ok(some_mnemomic) => some_mnemomic,
		Err(err) => return Err(PyValueError::new_err(format!("Invalid mnemonic: {}", err.to_string())))
	};
	let mut result = [0u8; 64];

    pbkdf2::<Hmac<Sha512>>(mnemonic.entropy(), salt.as_bytes(), 2048, &mut result);

    Ok(result[..32].to_vec())
}

/// Generates a new mnemonic phrase.
///
/// This function creates a new mnemonic phrase with the specified number of words.
/// If no word count is provided, it defaults to 12 words.
///
/// # Arguments
///
/// * `words` - An optional `u32` specifying the number of words in the mnemonic.
///             Valid values are 12, 15, 18, 21, or 24. Defaults to 12 if not provided.
///
/// # Returns
///
/// Returns a `PyResult<String>` containing the generated mnemonic phrase.
///
/// # Errors
///
/// This function will return an error if:
/// * An invalid number of words is provided (not 12, 15, 18, 21, or 24).
///
/// # Examples
///
/// ```
/// let mnemonic = generate_mnemonic(None).unwrap();
/// assert_eq!(mnemonic.split_whitespace().count(), 12);
///
/// let mnemonic = generate_mnemonic(Some(24)).unwrap();
/// assert_eq!(mnemonic.split_whitespace().count(), 24);
/// ```
fn generate_mnemonic(words: Option<u32>) -> PyResult<String> {
    let words = words.unwrap_or(12);
    
    let mnemonic_type = match words {
        12 => MnemonicType::Words12,
        15 => MnemonicType::Words15,
        18 => MnemonicType::Words18,
        21 => MnemonicType::Words21,
        24 => MnemonicType::Words24,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid number of words. Must be 12, 15, 18, 21, or 24.")),
    };
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
    
    Ok(mnemonic.to_string())
}


/// Validates a mnemonic phrase.
///
/// # Arguments
///
/// * `mnemonic` - A string slice containing the mnemonic phrase to validate.
/// * `language_code` - An optional `String` specifying the language code of the mnemonic.
///                     Defaults to "en" (English) if not provided.
///
/// # Returns
///
/// Returns a `PyResult<bool>` indicating whether the mnemonic is valid.
///
/// # Errors
///
/// This function will return an error if:
/// * An unsupported language code is provided.
///
/// # Examples
///
/// ```
/// let mnemonic = "toward also shift move pet nuclear strike book outdoor pilot afford allow";
/// let is_valid = validate_mnemonic(mnemonic, None).unwrap();
/// assert!(is_valid);
/// ```
fn validate_mnemonic(mnemonic: &str, language_code: Option<String>) -> PyResult<bool> {
    let language_code = language_code.unwrap_or_else(|| String::from("en"));
    
    let language = match language_code.as_str() {
        "en" => Language::English,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unsupported language code")),
    };
    
    let is_valid = Mnemonic::from_phrase(mnemonic, language).is_ok();
    Ok(is_valid)
}


/// Creates a new `Keypair` from a mnemonic phrase.
///
/// # Arguments
///
/// * `mnemonic` - A string slice containing the mnemonic phrase.
/// * `ss58_format` - An optional SS58 format. Defaults to 42 if not provided.
/// * `crypto_type` - An optional crypto type. Defaults to 1 (SR25519) if not provided.
/// * `language_code` - An optional language code for the mnemonic. Defaults to "en" (English) if not provided.
///
/// # Returns
///
/// Returns a `PyResult<Keypair>` containing the created keypair if successful, or a Python error if an error occurs.
///
/// # Errors
///
/// This function will return an error if:
/// * The mnemonic is invalid.
/// * The seed generation fails.
/// * The keypair creation from the seed fails.
fn create_from_mnemonic(mnemonic: &str, ss58_format: Option<u16>, crypto_type: Option<u8>, language_code: Option<String>) -> PyResult<Keypair> {
    let ss58_format = ss58_format.unwrap_or(42);
    let crypto_type = crypto_type.unwrap_or(1); // Default to SR25519
    
    // Default to English if language_code is None
    let language_code = language_code.as_deref().unwrap_or("en");

    let seed_array = bip39_to_mini_secret(mnemonic, "", Some(language_code))?;
    let seed_hex = hex::encode(&seed_array);
    let mut keypair = create_from_seed(&seed_hex, Some(ss58_format), Some(crypto_type))?;
    keypair.mnemonic = Some(mnemonic.to_string());
    Ok(keypair)
}

/// Creates a new `Keypair` from a seed.
///
/// # Arguments
///
/// * `seed_hex` - A hexadecimal string representing the seed.
/// * `ss58_format` - An optional SS58 format. Defaults to 42 if not provided.
/// * `crypto_type` - An optional crypto type. Defaults to 1 (SR25519) if not provided.
///
/// # Returns
///
/// Returns a `PyResult<Keypair>` containing the created keypair if successful, or a Python error if an error occurs.
///
/// # Errors
///
/// This function will return an error if:
/// * The seed hex is invalid.
/// * The seed bytes cannot be converted to a `Seed`.
/// * An unsupported crypto type is provided.
/// * ED25519 is requested (currently not implemented).
fn create_from_seed(seed_hex: &str, ss58_format: Option<u16>, crypto_type: Option<u8>) -> PyResult<Keypair> {
    let ss58_format = ss58_format.unwrap_or(42);
    let crypto_type = crypto_type.unwrap_or(1); // Default to SR25519

    let seed_bytes = hex::decode(seed_hex.trim_start_matches("0x"))
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hex in seed: {}", e)))?;
    let seed = Seed::from_bytes(&seed_bytes)
        .map_err(|e| PyValueError::new_err(e))?;

    let (public_key, private_key) = if crypto_type == 1 { // SR25519
        let Keypair(public_key, private_key) = pair_from_seed(seed);
        (public_key, private_key)
    } else if crypto_type == 0 { // ED25519
        // TODO: Implement ed25519_zebra.ed_from_seed
        // Placeholder: return an error for now
        return Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>("ED25519 not yet implemented"));
    } else {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("crypto_type '{}' not supported", crypto_type)));
    };

    let pub_key = PubKey(public_key);
    let ss58_address = ss58_encode(&pub_key, ss58_format);

    let keypair = Keypair {
        ss58_address: Some(ss58_address),
        public_key: pub_key.0.to_vec(),
        private_key: private_key.to_vec(),
        ss58_format: Some(ss58_format),
        crypto_type,
        seed_hex: Some(seed_hex.to_string()),
        mnemonic: None,
        derive_path: None,
    };

    Ok(keypair)
}