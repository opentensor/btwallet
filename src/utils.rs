use sp_core::crypto::Ss58Codec;
use pyo3::prelude::*;
use std::str;
use pyo3::types::{PyBytes, PyString, PyAny};
use crate::keypair::Keypair;
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

#[pyfunction]
pub fn is_valid_ed25519_pubkey(public_key: Option<&PyAny>) -> PyResult<bool> {
    Python::with_gil(|_py| {
        if let Some(pub_key) = public_key {
            if pub_key.is_instance_of::<PyString>() {
                let pub_key_string: &str = pub_key.extract()?;
                if pub_key_string.len() != 64 && pub_key_string.len() != 66 {
                    return Ok(false);
                }
            } else if pub_key.is_instance_of::<PyBytes>() {
                let pub_key_bytes: &[u8] = pub_key.extract()?;
                if pub_key_bytes.len() != 32 {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
            let pub_key_var = Some(pub_key.to_string());
            println!("{:?}", pub_key_var);
            let keypair_result = Keypair::new(None, pub_key_var, None, 42, None, 1);
            return match keypair_result {
                Ok(keypair) => {
                    if keypair.ss58_address()?.is_some() {
                        return Ok(true);
                    }
                        return Ok(false);
                },

                Err(_) =>  Ok(false),
            };
        }
        Ok(false)
    })
}

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

    #[test]
    fn test_is_valid_ed25519_pubkey() {
        Python::with_gil(|py| {
            let valid_key = PyString::new(py, "0891abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234");
            let res = is_valid_ed25519_pubkey(Some(valid_key.as_ref()));
            assert_eq!(res.unwrap(), true);

            let invalid_key = PyString::new(py, "invalid_key");
            let res = is_valid_ed25519_pubkey(Some(invalid_key.as_ref()));
            assert_eq!(res.unwrap(), false);
        });
    }
}