// External crates
use bip39::{Language, Mnemonic};
use rand::RngCore;
use schnorrkel::{
    derive::{ChainCode, Derivation},
    ExpansionMode, MiniSecretKey,
};
use sp_core::{sr25519, Pair};

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

/// Creates a new hotkey pair from a mnemonic phrase and name.
///
/// This function generates a new sr25519 key pair (hotkey) using the provided mnemonic and
/// a name for derivation.
///
/// # Arguments
///
/// * `mnemonic` - A `Mnemonic` object representing the seed phrase.
/// * `name` - A string slice used to create the derivation path.
///
/// # Returns
///
/// Returns an `sr25519::Pair` representing the derived hotkey pair.
///
/// # Panics
///
/// This function will panic if:
/// - The seed creation from the mnemonic fails.
/// - The key derivation process fails.
///
/// # Examples
///
/// ```
/// use bip39::Mnemonic;
/// let mnemonic = Mnemonic::from_phrase("your mnemonic phrase here", Language::English).unwrap();
/// let hotkey = create_hotkey(mnemonic, "my_hotkey");
/// ```
pub fn create_hotkey(mnemonic: Mnemonic, name: &str) -> sr25519::Pair {
    let seed: [u8; 32] = mnemonic.to_seed("")[..32]
        .try_into()
        .expect("Failed to create seed");

    let derivation_path: Vec<u8> = format!("//{}", name).into_bytes();

    let hotkey_pair: sr25519::Pair =
        derive_sr25519_key(&seed, &derivation_path).expect("Failed to derive sr25519 key");

    hotkey_pair
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic};
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
    fn test_create_hotkey() {
        let mnemonic = Mnemonic::parse_in_normalized(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let name = "test_hotkey";

        let hotkey = create_hotkey(mnemonic.clone(), name);

        // Check that the hotkey is not empty
        assert!(!hotkey.public().0.is_empty());

        // Check that creating the same hotkey twice produces the same result
        let hotkey2 = create_hotkey(mnemonic.clone(), name);
        assert_eq!(hotkey.public(), hotkey2.public());

        // Check that different names produce different hotkeys
        let hotkey3 = create_hotkey(mnemonic, "different_name");
        assert_ne!(hotkey.public(), hotkey3.public());
    }

    #[test]
    fn test_create_hotkey_different_mnemonics() {
        let mnemonic1 = Mnemonic::parse_in_normalized(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let mnemonic2 = Mnemonic::parse_in_normalized(
            Language::English,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        )
        .expect("Invalid mnemonic phrase");
        let name = "test_hotkey";

        let hotkey1 = create_hotkey(mnemonic1, name);
        let hotkey2 = create_hotkey(mnemonic2, name);

        // Check that different mnemonics produce different hotkeys
        assert_ne!(hotkey1.public(), hotkey2.public());
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
