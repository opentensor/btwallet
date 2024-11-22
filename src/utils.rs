use sp_core::crypto::{AccountId32, Ss58Codec};
use std::str;

use crate::keypair::Keypair;

pub(crate) const SS58_FORMAT: u8 = 42;

/// Returns the SS58 format of the given address string.
pub fn get_ss58_format(ss58_address: &str) -> Result<u16, &'static str> {
    match <AccountId32 as Ss58Codec>::from_ss58check_with_version(ss58_address) {
        Ok((_, format)) => Ok(u16::from(format)),
        Err(_) => Err("Invalid SS58 address."),
    }
}

/// Checks if the given address is a valid ss58 address.
///
/// Args:
///     address(str): The address to check.
///
/// Returns:
///     True if the address is a valid ss58 address for Bittensor, False otherwise.
pub fn is_valid_ss58_address(address: &str) -> bool {
    if address.is_empty() {
        // Possibly there could be a debug log, but not a print
        // utils::print(format!("The given address is empty"));
        return false;
    }

    match sp_core::sr25519::Public::from_ss58check(address) {
        Ok(_) => true,
        Err(_) => {
            // Possibly there could be a debug log, but not a print
            // utils::print(format!("Invalid SS58 address format"));
            false
        }
    }
}

///    Checks if the given public_key is a valid ed25519 key.
///
///     Args:
///         public_key: The public_key to check as string or bytes.
///
///     Returns:
///         True if the public_key is a valid ed25519 key, False otherwise.
pub fn is_valid_ed25519_pubkey(public_key: &[u8]) -> bool {
    if public_key.len() != 32 {
        return false;
    }

    let pub_key_var = Some(hex::encode(public_key));
    let keypair_result = Keypair::new(None, pub_key_var, None, SS58_FORMAT, None, 1);

    match keypair_result {
        Ok(keypair) => {
            if let Some(_) = keypair.ss58_address() {
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

///    Checks if the given address is a valid destination address.
///
///     Args:
///         address(Union[str, bytes]): The address to check.
///
///     Returns:
///         True if the address is a valid destination address, False otherwise.
pub fn is_valid_bittensor_address_or_public_key(address: &str) -> bool {
    if address.starts_with("0x") {
        // Convert hex string to bytes
        if let Ok(bytes) = hex::decode(&address[2..]) {
            is_valid_ed25519_pubkey(&bytes)
        } else {
            false
        }
    } else {
        is_valid_ss58_address(address)
    }
}

pub fn print(s: String) {
    use std::io::{self, Write};
    print!("{}", s);
    io::stdout().flush().unwrap();
}

/// Prompts the user and returns the response, if any.
///    
/// Args:
///     prompt: String
///
/// Returns:
///     response: Option<String>
pub fn prompt(prompt: String) -> Option<String> {
    use std::io::{self, Write};
    
    print!("{}", prompt);
    io::stdout().flush().ok()?;
    
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => Some(input.trim().to_string()),
        Err(_) => None
    }
}

/// Prompts the user with a password entry and returns the response, if any.
///    
/// Args:
///     prompt (String): the prompt to ask the user with.
///
/// Returns:
///     response: Option<String>
pub fn prompt_password(prompt: String) -> Option<String> {
    use std::io::{self, Write};
    use rpassword::read_password;

    print!("{}", prompt);
    io::stdout().flush().ok()?;

    match read_password() {
        Ok(password) => Some(password.trim().to_string()),
        Err(_) => None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ss58_format_success() {
        let test_address = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
        assert_eq!(is_valid_ss58_address(test_address), true);
    }
}
