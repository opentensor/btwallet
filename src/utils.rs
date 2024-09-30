use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::str;

use crate::keypair::Keypair;

pub(crate) const SS58_FORMAT: u8 = 42;

/// Returns the SS58 format of the given address string.
#[pyfunction]
pub fn get_ss58_format(ss58_address: &str) -> PyResult<u16> {
    match <AccountId32 as sp_core::crypto::Ss58Codec>::from_ss58check_with_version(ss58_address) {
        Ok((_, format)) => Ok(u16::from(format)),
        Err(_) => Err(pyo3::exceptions::PyValueError::new_err(
            "Invalid SS58 address.",
        )),
    }
}

/// Checks if the given address is a valid ss58 address.
///
/// Args:
///     address(str): The address to check.
///
/// Returns:
///     True if the address is a valid ss58 address for Bittensor, False otherwise.
#[pyfunction]
pub fn is_valid_ss58_address(address: &str) -> PyResult<bool> {
    if address.is_empty() {
        // Possibly there could be a debug log, but not a print
        // println!("The given address is empty");
        return Ok(false);
    }

    match sp_core::sr25519::Public::from_ss58check(address) {
        Ok(_) => Ok(true),
        Err(_) => {
            // Possibly there could be a debug log, but not a print
            // println!("Invalid SS58 address format");
            Ok(false)
        }
    }
}

///    Checks if the given public_key is a valid ed25519 key.
///
///     Args:
///         public_key(Union[str, bytes]): The public_key to check.
///
///     Returns:
///         True if the public_key is a valid ed25519 key, False otherwise.
#[pyfunction]
pub fn is_valid_ed25519_pubkey(public_key: &Bound<'_, PyAny>) -> PyResult<bool> {
    Python::with_gil(|_py| {
        if public_key.is_instance_of::<PyString>() {
            let pub_key_string: &str = public_key.extract()?;
            if pub_key_string.len() != 64 && pub_key_string.len() != 66 {
                // Possibly need to log the error for debug (a public_key should be 64 or 66 characters)
                return Ok(false);
            }
        } else if public_key.is_instance_of::<PyBytes>() {
            let pub_key_bytes: &[u8] = public_key.extract()?;
            if pub_key_bytes.len() != 32 {
                // Possibly need to log the error for debug (a public_key should be 32 bytes)
                return Ok(false);
            }
        } else {
            // Possibly need to log the error for debug (public_key must be a string or bytes)
            return Ok(false);
        }

        let pub_key_var = Some(public_key.to_string());

        let keypair_result = Keypair::new(None, pub_key_var, None, SS58_FORMAT, None, 1);

        match keypair_result {
            Ok(keypair) => {
                if keypair.ss58_address()?.is_some() {
                    return Ok(true);
                }
                Ok(false)
            }
            Err(_) => Ok(false),
        }
    })
}

///    Checks if the given address is a valid destination address.
///
///     Args:
///         address(Union[str, bytes]): The address to check.
///
///     Returns:
///         True if the address is a valid destination address, False otherwise.
#[pyfunction]
pub fn is_valid_bittensor_address_or_public_key(address: &Bound<'_, PyAny>) -> PyResult<bool> {
    Python::with_gil(|_py| {
        if address.is_instance_of::<PyString>() {
            let address_str = &address.to_string();
            if address_str.starts_with("0x") {
                is_valid_ed25519_pubkey(address)
            } else {
                is_valid_ss58_address(address_str)
            }
        } else if address.is_instance_of::<PyBytes>() {
            is_valid_ed25519_pubkey(address)
        } else {
            Ok(false)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ss58_format_success() {
        let test_address = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
        match is_valid_ss58_address(test_address) {
            Ok(result) => assert_eq!(result, true),
            Err(err) => panic!("Test failed with error: {:?}", err),
        }
    }
}
