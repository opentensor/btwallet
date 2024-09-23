use sp_core::crypto::Ss58Codec;
use pyo3::prelude::*;
use std::str;

// use pyo3::exceptions::PyException;
// use crate::keypair::Keypair;
// use pyo3::{pyfunction, pymethods, pymodule, wrap_pyfunction, PyErr, PyResult, Python};
// use pyo3::prelude::PyModule;
// use sp_core::crypto::Ss58Codec;
// use sp_core::crypto::Ss58AddressFormat;
// use sp_core::crypto::Pair;
// use sp_core::sr25519;


// const SS58_FORMAT: u8 = 42;


// /// Returns the SS58 format of the given address string.
// #[pyfunction]
// pub fn get_ss58_format(ss58_address: &str) -> PyResult<u16> {
//     // Decode the SS58 address
//     let maybe_address = Ss58Codec::from_string(ss58_address);
//     match maybe_address {
//         Ok(decoded_address) => {
//             // The version (or format) information is stored in the decoded_address.
//             // Use `decoded_address.ss58_version()` to access it.
//             Ok(10)
//         },
//         Err(e) => {
//             Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
//                 format!("error while decoding SS58 address: {}", e)
//             ))
//         },
//     }
// }

// #[pymodule(name="utils")]
// fn utils(m: &Bound<'_, PyModule>) -> PyResult<()> {
//     m.add_function(wrap_pyfunction!(get_ss58_format, m)?)?;
//     Ok(())
// }

/// Function to validate a given SS58 address
#[pyfunction]
pub fn is_valid_ss58_address(address: &str) -> PyResult<bool> {
    if address.is_empty() {
        // hypothetically there could be a debug log, but not a print
        // println!("The given address is empty");
        return Ok(false);
    }

    match sp_core::sr25519::Public::from_ss58check(address) {
        Ok(_) => Ok(true),
        Err(_) => {
            // hypothetically there could be a debug log, but not a print
            // println!("Invalid SS58 address format");
            Ok(false)
        }
    }
}

//
// fn is_valid_ed25519_pubkey(public_key: &str) -> bool {
//     let valid_length = public_key.len() == 64 || public_key.len() == 66;
//     if valid_length { // TODO: when keypair supports
//         // let keypair = Keypair::public_key(public_key);
//         // match keypair {
//         //     Ok(_) => return true,
//         //     Err(_) => return false,
//         // }
//     }
//     false
// }

// // #[pyfunction]
// fn is_valid_bittensor_address_or_public_key(address: &[u8]) -> Result<bool, &'static str> {
//     match str::from_utf8(address) {
//         Ok(a) => {
//             if a.starts_with("0x") {
//                 Ok(is_valid_ed25519_pubkey(a))
//             } else {
//                 Ok(is_valid_ss58_address(a))
//             }
//         },
//         Err(_) => Err("Not a valid string"),
//     }
// }

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