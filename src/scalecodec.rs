use base58::ToBase58;
use blake2::{Blake2b, Digest};
use generic_array::typenum::U64;
use generic_array::GenericArray;

use crate::sr25519::PubKey;

/// Encodes a public key into an SS58 address format.
///
/// # Arguments
///
/// * `address` - A reference to a `PubKey` containing the public key to encode.
/// * `ss58_format` - A u16 value representing the SS58 format to use.
///
/// # Returns
///
/// A `String` containing the SS58-encoded address.
///
/// # Errors
///
/// Returns an error string if:
/// - The `ss58_format` is invalid (> 16383 or == 46 or == 47)
/// - The address length is invalid
pub fn ss58_encode(address: &PubKey, ss58_format: u16) -> String {
    let checksum_prefix = b"SS58PRE";

    if ss58_format > 16383 || ss58_format == 46 || ss58_format == 47 {
        return "Invalid value for ss58_format".to_string();
    }

    let address_bytes = address;
    let checksum_length = match address_bytes.0.len() {
        32 | 33 => 2,
        1 | 2 | 4 | 8 => 1,
        _ => return "Invalid length for address".to_string(),
    };

    let ss58_format_bytes = if ss58_format < 64 {
        vec![ss58_format as u8]
    } else {
        vec![
            ((ss58_format & 0b0000_0000_1111_1100) >> 2) as u8 | 0b0100_0000,
            ((ss58_format >> 8) | ((ss58_format & 0b0000_0000_0000_0011) << 6)) as u8,
        ]
    };

    let mut input_bytes = ss58_format_bytes;
    input_bytes.extend_from_slice(address.as_bytes());

    let mut hasher = Blake2b::new();
    hasher.update(checksum_prefix);
    hasher.update(&input_bytes);
    let checksum: GenericArray<u8, U64> = hasher.finalize();

    input_bytes.extend_from_slice(&checksum[..checksum_length]);

    input_bytes.to_base58()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ss58_encode_valid() {
        let pubkey = PubKey([1u8; 32]);
        let ss58_format = 42; // Substrate
        let result = ss58_encode(&pubkey, ss58_format);
        assert!(!result.is_empty());
        assert_ne!(result, "Invalid value for ss58_format");
        assert_ne!(result, "Invalid length for address");
    }

    #[test]
    fn test_ss58_encode_invalid_format() {
        let pubkey = PubKey([1u8; 32]);
        let ss58_format = 16384; // Invalid
        let result = ss58_encode(&pubkey, ss58_format);
        assert_eq!(result, "Invalid value for ss58_format");
    }

    #[test]
    fn test_ss58_encode_invalid_address_length() {
        let pubkey = PubKey([1u8; 31]); // Invalid length
        let ss58_format = 42;
        let result = ss58_encode(&pubkey, ss58_format);
        assert_eq!(result, "Invalid length for address");
    }

    #[test]
    fn test_ss58_encode_different_formats() {
        let pubkey = PubKey([1u8; 32]);
        let format1 = 0;
        let format2 = 42;
        let result1 = ss58_encode(&pubkey, format1);
        let result2 = ss58_encode(&pubkey, format2);
        assert_ne!(result1, result2);
    }
}
