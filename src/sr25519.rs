use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
use schnorrkel::{MINI_SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

/// Represents a keypair containing a public key and a secret key.
pub struct Keypair(pub [u8; PUBLIC_KEY_LENGTH], pub [u8; SECRET_KEY_LENGTH]);

/// Represents a seed used for key generation.
pub struct Seed([u8; MINI_SECRET_KEY_LENGTH]);

/// Represents a private key.
pub struct PrivKey(pub [u8; SECRET_KEY_LENGTH]);

/// Represents a public key.
pub struct PubKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl Seed {
    /// Creates a new Seed from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A slice of bytes to create the seed from.
    ///
    /// # Returns
    ///
    /// * `Result<Self, &'static str>` - A Result containing the Seed if successful, or an error message if the input is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != MINI_SECRET_KEY_LENGTH {
            return Err("Invalid seed length");
        }
        let mut arr = [0u8; MINI_SECRET_KEY_LENGTH];
        arr.copy_from_slice(bytes);
        Ok(Seed(arr))
    }
}

impl PubKey {
    /// Returns the public key as a byte slice.
    ///
    /// # Returns
    ///
    /// * `&[u8]` - A slice of bytes representing the public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Generates a keypair from a seed.
///
/// # Arguments
///
/// * `seed` - A Seed struct to generate the keypair from.
///
/// # Returns
///
/// * `Keypair` - A Keypair struct containing the generated public and secret keys.
pub fn pair_from_seed(seed: Seed) -> Keypair {
    let k = MiniSecretKey::from_bytes(&seed.0).expect("32 bytes can always build a key; qed");
    let kp = k.expand_to_keypair(ExpansionMode::Ed25519);

    Keypair(kp.public.to_bytes(), kp.secret.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_from_bytes() {
        let valid_bytes = [0u8; MINI_SECRET_KEY_LENGTH];
        let result = Seed::from_bytes(&valid_bytes);
        assert!(result.is_ok());

        let invalid_bytes = [0u8; MINI_SECRET_KEY_LENGTH - 1];
        let result = Seed::from_bytes(&invalid_bytes);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid seed length");
    }

    #[test]
    fn test_pubkey_as_bytes() {
        let pubkey_bytes = [1u8; PUBLIC_KEY_LENGTH];
        let pubkey = PubKey(pubkey_bytes);
        assert_eq!(pubkey.as_bytes(), &pubkey_bytes);
    }

    #[test]
    fn test_pair_from_seed() {
        let seed_bytes = [0u8; MINI_SECRET_KEY_LENGTH];
        let seed = Seed::from_bytes(&seed_bytes).unwrap();
        let keypair = pair_from_seed(seed);

        assert_eq!(keypair.0.len(), PUBLIC_KEY_LENGTH);
        assert_eq!(keypair.1.len(), SECRET_KEY_LENGTH);

        assert_ne!(keypair.0, [0u8; PUBLIC_KEY_LENGTH]);
    }
}
