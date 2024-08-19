// External crates
use bip39::{Language, Mnemonic, MnemonicType};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use primitive_types::U256;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use sha2::Sha512;

// Internal modules
use crate::scalecodec::*;
use crate::sr25519::*;

/// Represents a cryptographic keypair with associated metadata.
///
/// This struct encapsulates various components of a cryptographic keypair,
/// including the public and private keys, as well as additional information
/// such as the cryptographic type, derivation path, and address format.
///
/// # Fields
///
/// * `crypto_type`: The type of cryptography used (e.g., 0 for Ed25519, 1 for SR25519).
/// * `seed_hex`: An optional hexadecimal representation of the seed used to generate the keypair.
/// * `derive_path`: An optional derivation path used to generate the keypair from a master key.
/// * `ss58_format`: An optional SS58 address format identifier.
/// * `public_key`: The public key as a vector of bytes.
/// * `ss58_address`: An optional SS58-encoded address derived from the public key.
/// * `private_key`: The private key as a vector of bytes.
/// * `mnemonic`: An optional mnemonic phrase used to generate the keypair.
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

/// Parses a derivation path string into a vector of u32 values.
///
/// This function takes a BIP32 derivation path string and converts it into a vector of u32 values
/// that represent the path components. It supports both normal and hardened derivation.
///
/// # Arguments
///
/// * `str_derivation_path` - A string slice containing the derivation path.
///
/// # Returns
///
/// Returns a `PyResult<Vec<u32>>` containing the parsed derivation path components.
///
/// # Errors
///
/// This function will return an error if:
/// * The derivation path doesn't start with "m/".
/// * Any component of the path fails to parse as a u32.
///
/// # Examples
///
/// ```
/// let path = "m/44'/60/0'/0";
/// let parsed = parse_derivation_path(path).unwrap();
/// assert_eq!(parsed, vec![2147483692, 60, 2147483648, 0]);
/// ```
fn parse_derivation_path(str_derivation_path: &str) -> PyResult<Vec<u32>> {
    if !str_derivation_path.starts_with("m/") {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Can't recognize derivation path. It should look like \"m/44'/60/0'/0\".",
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

/// Converts a BIP39 seed to a BIP32 master node.
///
/// This function takes a BIP39 seed and generates the master private key and chain code
/// for a BIP32 hierarchical deterministic wallet.
///
/// # Arguments
///
/// * `seed` - A byte slice containing the BIP39 seed.
///
/// # Returns
///
/// A tuple containing two 32-byte arrays:
/// * The first array is the master private key.
/// * The second array is the master chain code.
///
/// # Examples
///
/// ```
/// let seed = [0u8; 64]; // Example seed
/// let (master_key, master_chain_code) = bip39seed_to_bip32masternode(&seed);
/// assert_eq!(master_key.len(), 32);
/// assert_eq!(master_chain_code.len(), 32);
/// ```
///
/// # Note
///
/// This function uses HMAC-SHA512 with the key "Bitcoin seed" as specified in the BIP32 standard.
fn bip39seed_to_bip32masternode(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    const BIP32_SEED_MODIFIER: &[u8] = b"Bitcoin seed";

    let mut mac =
        Hmac::<Sha512>::new_from_slice(BIP32_SEED_MODIFIER).expect("HMAC can take key of any size");
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
fn derive_bip32childkey(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    i: u32,
) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use secp256k1::{PublicKey, Secp256k1};
    use sha2::Sha512;

    assert_eq!(parent_key.len(), 32);
    assert_eq!(parent_chain_code.len(), 32);

    let k = parent_chain_code;
    let key = if (i & 0x80000000) != 0 {
        let mut key = [0u8; 33];
        key[1..].copy_from_slice(parent_key);
        key
    } else {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(parent_key).unwrap(),
        );
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
pub fn bip39_to_mini_secret(
    phrase: &str,
    password: &str,
    language_code: Option<&str>,
) -> PyResult<Vec<u8>> {
    let salt = format!("mnemonic{}", password);

    let language = match Language::from_language_code(language_code.unwrap_or("en")) {
        Some(language) => language,
        None => return Err(PyValueError::new_err("Invalid language_code")),
    };

    let mnemonic = match Mnemonic::from_phrase(phrase, language) {
        Ok(some_mnemomic) => some_mnemomic,
        Err(err) => {
            return Err(PyValueError::new_err(format!(
                "Invalid mnemonic: {}",
                err.to_string()
            )))
        }
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
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid number of words. Must be 12, 15, 18, 21, or 24.",
            ))
        }
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
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Unsupported language code",
            ))
        }
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
fn create_from_mnemonic(
    mnemonic: &str,
    ss58_format: Option<u16>,
    crypto_type: Option<u8>,
    language_code: Option<String>,
) -> PyResult<Keypair> {
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
fn create_from_seed(
    seed_hex: &str,
    ss58_format: Option<u16>,
    crypto_type: Option<u8>,
) -> PyResult<Keypair> {
    let ss58_format = ss58_format.unwrap_or(42);
    let crypto_type = crypto_type.unwrap_or(1); // Default to SR25519

    let seed_bytes = hex::decode(seed_hex.trim_start_matches("0x")).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid hex in seed: {}", e))
    })?;
    let seed = Seed::from_bytes(&seed_bytes).map_err(|e| PyValueError::new_err(e))?;

    let (public_key, private_key) = if crypto_type == 1 {
        // SR25519
        let Keypair(public_key, private_key) = pair_from_seed(seed);
        (public_key, private_key)
    } else if crypto_type == 0 {
        // ED25519
        // TODO: Implement ed25519_zebra.ed_from_seed
        // Placeholder: return an error for now
        return Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
            "ED25519 not yet implemented",
        ));
    } else {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "crypto_type '{}' not supported",
            crypto_type
        )));
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_parse_derivation_path_valid() {
        let path = "m/44'/60/0'/0";
        let result = parse_derivation_path(path).unwrap();
        assert_eq!(result, vec![2147483692, 60, 2147483648, 0]);
    }

    #[test]
    fn test_parse_derivation_path_invalid_start() {
        let path = "44'/60/0'/0";
        let result = parse_derivation_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_derivation_path_mixed() {
        let path = "m/44'/60/0/1'";
        let result = parse_derivation_path(path).unwrap();
        assert_eq!(result, vec![2147483692, 60, 0, 2147483649]);
    }

    #[test]
    fn test_parse_derivation_path_invalid_component() {
        let path = "m/44'/60/invalid/0";
        let result = parse_derivation_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_bip39seed_to_bip32masternode() {
        // Test vector from BIP32 specification
        let seed = hex!("000102030405060708090a0b0c0d0e0f");
        let expected_master_key =
            hex!("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let expected_chain_code =
            hex!("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");

        let (master_key, chain_code) = bip39seed_to_bip32masternode(&seed);

        assert_eq!(master_key, expected_master_key);
        assert_eq!(chain_code, expected_chain_code);
    }

    #[test]
    fn test_bip39seed_to_bip32masternode_different_seeds() {
        let seed1 = [0u8; 64];
        let seed2 = [1u8; 64];

        let (master_key1, chain_code1) = bip39seed_to_bip32masternode(&seed1);
        let (master_key2, chain_code2) = bip39seed_to_bip32masternode(&seed2);

        assert_ne!(master_key1, master_key2);
        assert_ne!(chain_code1, chain_code2);
    }

    #[test]
    fn test_derive_bip32childkey_normal() {
        let parent_key = [1u8; 32];
        let parent_chain_code = [2u8; 32];
        let child_index = 0;

        let (child_key, child_chain_code) =
            derive_bip32childkey(&parent_key, &parent_chain_code, child_index);

        assert_eq!(child_key.len(), 32);
        assert_eq!(child_chain_code.len(), 32);
        assert_ne!(child_key, parent_key);
        assert_ne!(child_chain_code, parent_chain_code);
    }

    #[test]
    fn test_derive_bip32childkey_hardened() {
        let parent_key = [3u8; 32];
        let parent_chain_code = [4u8; 32];
        let child_index = 0x80000000; // Hardened derivation

        let (child_key, child_chain_code) =
            derive_bip32childkey(&parent_key, &parent_chain_code, child_index);

        assert_eq!(child_key.len(), 32);
        assert_eq!(child_chain_code.len(), 32);
        assert_ne!(child_key, parent_key);
        assert_ne!(child_chain_code, parent_chain_code);
    }

    #[test]
    fn test_derive_bip32childkey_different_indexes() {
        let parent_key = [5u8; 32];
        let parent_chain_code = [6u8; 32];
        let child_index_1 = 1;
        let child_index_2 = 2;

        let (child_key_1, child_chain_code_1) =
            derive_bip32childkey(&parent_key, &parent_chain_code, child_index_1);
        let (child_key_2, child_chain_code_2) =
            derive_bip32childkey(&parent_key, &parent_chain_code, child_index_2);

        assert_ne!(child_key_1, child_key_2);
        assert_ne!(child_chain_code_1, child_chain_code_2);
    }

    #[test]
    fn test_mnemonic_to_bip39seed() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "TREZOR";

        let expected_seed = [
            0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x55, 0x16, 0xc5, 0xba, 0x49, 0x8a,
            0xb8, 0x4a, 0xe8, 0xb6, 0x1e, 0xab, 0x45, 0x85, 0x97, 0x16, 0x4b, 0xf4, 0x42, 0x08,
            0x8c, 0x70, 0x32, 0x98, 0x1b, 0x9c, 0x5d, 0xb6, 0xc3, 0x9b, 0xbf, 0x0d, 0x75, 0x8d,
            0x6b, 0x68, 0x53, 0x3e, 0xc4, 0x10, 0x5d, 0x72, 0xc5, 0x18, 0x36, 0x83, 0xaf, 0x2c,
            0x0a, 0x5f, 0x67, 0x58, 0x9d, 0x13, 0xc8, 0x4e,
        ];

        let result = mnemonic_to_bip39seed(mnemonic, passphrase);
        assert_eq!(result, expected_seed);
    }
    #[test]
    fn test_bip39_to_mini_secret() {
        let phrase = "toward also shift move pet nuclear strike book outdoor pilot afford allow";
        let password = "";
        let mini_secret = bip39_to_mini_secret(phrase, password, None).unwrap();
        assert_eq!(mini_secret.len(), 32);

        // Test with a different language
        let phrase_fr = "abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser aboyer";
        let mini_secret_fr = bip39_to_mini_secret(phrase_fr, password, Some("fr")).unwrap();
        assert_eq!(mini_secret_fr.len(), 32);

        // Test with an invalid mnemonic
        let invalid_phrase = "invalid mnemonic phrase";
        assert!(bip39_to_mini_secret(invalid_phrase, password, None).is_err());

        // Test with an invalid language code
        assert!(bip39_to_mini_secret(phrase, password, Some("invalid")).is_err());
    }
    #[test]
    fn test_generate_mnemonic() {
        // Test default case (12 words)
        let mnemonic = generate_mnemonic(None).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);

        // Test all valid word counts
        for &words in &[12, 15, 18, 21, 24] {
            let mnemonic = generate_mnemonic(Some(words)).unwrap();
            assert_eq!(mnemonic.split_whitespace().count(), words as usize);
        }

        // Test invalid word count
        assert!(generate_mnemonic(Some(16)).is_err());
    }
    #[test]
    fn test_validate_mnemonic() {
        let valid_mnemonic =
            "toward also shift move pet nuclear strike book outdoor pilot afford allow";
        assert!(validate_mnemonic(valid_mnemonic, None).unwrap());

        let invalid_mnemonic = "invalid mnemonic phrase";
        assert!(!validate_mnemonic(invalid_mnemonic, None).unwrap());

        let valid_mnemonic_es =
            "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abogado";
        assert!(validate_mnemonic(valid_mnemonic_es, Some("es".to_string())).is_err());

        let result = validate_mnemonic(valid_mnemonic, Some("invalid_language".to_string()));
        assert!(result.is_err());
    }
    #[test]
    fn test_create_from_mnemonic() {
        let mnemonic = "toward also shift move pet nuclear strike book outdoor pilot afford allow";
        let result = create_from_mnemonic(mnemonic, None, None, None);
        assert!(result.is_ok());

        let keypair = result.unwrap();
        assert_eq!(keypair.ss58_format, Some(42));
        assert_eq!(keypair.crypto_type, 1);
        assert_eq!(keypair.mnemonic, Some(mnemonic.to_string()));
        assert!(keypair.seed_hex.is_some());
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.private_key.is_empty());
        assert!(keypair.ss58_address.is_some());
    }
    #[test]
    fn test_create_from_seed_valid() {
        let seed_hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = create_from_seed(seed_hex, None, None);
        assert!(result.is_ok());
        let keypair = result.unwrap();
        assert_eq!(keypair.ss58_format, Some(42));
        assert_eq!(keypair.crypto_type, 1);
        assert_eq!(keypair.seed_hex, Some(seed_hex.to_string()));
    }

    #[test]
    fn test_create_from_seed_invalid_hex() {
        let seed_hex = "invalid_hex";
        let result = create_from_seed(seed_hex, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_from_seed_custom_ss58_format() {
        let seed_hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = create_from_seed(seed_hex, Some(2), None);
        assert!(result.is_ok());
        let keypair = result.unwrap();
        assert_eq!(keypair.ss58_format, Some(2));
    }

    #[test]
    fn test_create_from_seed_unsupported_crypto_type() {
        let seed_hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = create_from_seed(seed_hex, None, Some(2));
        assert!(result.is_err());
    }

    #[test]
    fn test_create_from_seed_ed25519() {
        let seed_hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = create_from_seed(seed_hex, None, Some(0));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ED25519 not yet implemented"));
    }
}
