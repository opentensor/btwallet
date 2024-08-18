// use pyo3::prelude::*;
// use pyo3::types::{PyBytes, PyString};
// use pyo3::exceptions::PyValueError;
// use std::convert::TryFrom;
// use bip39::{Mnemonic, MnemonicType, Language };
// use hmac::Hmac;
// use pbkdf2::pbkdf2;
// use sha2::Sha512;
// use uint::U256; 

// use crate::sr25519::*;

// use crate::scalecodec::*;


// #[pyclass]
// pub struct Keypair {
//     #[pyo3(get, set)]
//     crypto_type: u8,
//     #[pyo3(get, set)]
//     seed_hex: Option<String>,
//     #[pyo3(get, set)]
//     derive_path: Option<String>,
//     #[pyo3(get, set)]
//     ss58_format: Option<u16>,
//     #[pyo3(get, set)]
//     public_key: Vec<u8>,
//     #[pyo3(get, set)]
//     ss58_address: Option<String>,
//     #[pyo3(get, set)]
//     private_key: Option<Vec<u8>>,
//     #[pyo3(get, set)]
//     mnemonic: Option<String>,
// }


// fn parse_derivation_path(str_derivation_path: &str) -> PyResult<Vec<u32>> {
//     if !str_derivation_path.starts_with("m/") {
//         return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
//             "Can't recognize derivation path. It should look like \"m/44'/60/0'/0\"."
//         ));
//     }

//     let mut path = Vec::new();
//     for component in str_derivation_path.trim_start_matches("m/").split('/') {
//         if component.ends_with('\'') {
//             let value = component.trim_end_matches('\'').parse::<u32>()?;
//             path.push(0x80000000 + value); // BIP32_PRIVDEV + int(i[:-1])
//         } else {
//             path.push(component.parse::<u32>()?);
//         }
//     }

//     Ok(path)
// }


// fn bip39seed_to_bip32masternode(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
//     use hmac::{Hmac, Mac};
//     use sha2::Sha512;

//     const BIP32_SEED_MODIFIER: &[u8] = b"Bitcoin seed";

//     let mut mac = Hmac::<Sha512>::new_from_slice(BIP32_SEED_MODIFIER)
//         .expect("HMAC can take key of any size");
//     mac.update(seed);
//     let result = mac.finalize().into_bytes();

//     let (key, chain_code) = result.split_at(32);
//     (key.try_into().unwrap(), chain_code.try_into().unwrap())
// }

// fn derive_bip32childkey(parent_key: &[u8; 32], parent_chain_code: &[u8; 32], i: u32) -> ([u8; 32], [u8; 32]) {
//     use hmac::{Hmac, Mac};
//     use sha2::Sha512;
//     use secp256k1::{PublicKey, Secp256k1};

//     assert_eq!(parent_key.len(), 32);
//     assert_eq!(parent_chain_code.len(), 32);

//     let k = parent_chain_code;
//     let key = if (i & 0x80000000) != 0 {
//         let mut key = [0u8; 33];
//         key[1..].copy_from_slice(parent_key);
//         key
//     } else {
//         let secp = Secp256k1::new();
//         let public_key = PublicKey::from_secret_key(&secp, &secp256k1::SecretKey::from_slice(parent_key).unwrap());
//         public_key.serialize()
//     };

//     let mut d = Vec::with_capacity(key.len() + 4);
//     d.extend_from_slice(&key);
//     d.extend_from_slice(&i.to_be_bytes());

//     loop {
//         let mut mac = Hmac::<Sha512>::new_from_slice(k).expect("HMAC can take key of any size");
//         mac.update(&d);
//         let h = mac.finalize().into_bytes();

//         let (key, chain_code) = h.split_at(32);
//         let a = U256::from_big_endian(key);  // Use U256 instead of u256
//         let b = U256::from_big_endian(parent_key);
//         let key = (a + b) % U256::from(secp256k1::constants::CURVE_ORDER);

//         if a < U256::from(secp256k1::constants::CURVE_ORDER) && key != U256::zero() {
//             let mut key_bytes = [0u8; 32];
//             key.to_big_endian(&mut key_bytes);
//             return (key_bytes, chain_code.try_into().unwrap());
//         }

//         d = vec![0x01];
//         d.extend_from_slice(&h[32..]);
//         d.extend_from_slice(&i.to_be_bytes());
//     }
// }


// pub fn mnemonic_to_ecdsa_private_key(mnemonic: &str, str_derivation_path: Option<&str>, passphrase: &str) -> PyResult<[u8; 32]> {
//     let str_derivation_path = str_derivation_path.unwrap_or("m/44'/60'/0'/0/0");

//     let derivation_path = parse_derivation_path(str_derivation_path)?;
//     let bip39seed = mnemonic_to_bip39seed(mnemonic, passphrase);
//     let (master_private_key, master_chain_code) = bip39seed_to_bip32masternode(&bip39seed);
//     let (mut private_key, mut chain_code) = (master_private_key, master_chain_code);

//     for i in derivation_path {
//         let (new_private_key, new_chain_code) = derive_bip32childkey(&private_key, &chain_code, i);
//         private_key = new_private_key;
//         chain_code = new_chain_code;
//     }

//     Ok(private_key)
// }

// // fn parse_derivation_path(str_derivation_path: &str) -> PyResult<Vec<u32>> {
// //     if !str_derivation_path.starts_with("m/") {
// //         return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
// //             "Can't recognize derivation path. It should look like \"m/44'/60/0'/0\"."
// //         ));
// //     }

// //     let mut path = Vec::new();
// //     for component in str_derivation_path.trim_start_matches("m/").split('/') {
// //         if component.ends_with('\'') {
// //             let value = component.trim_end_matches('\'').parse::<u32>()?;
// //             path.push(0x80000000 + value);
// //         } else {
// //             path.push(component.parse::<u32>()?);
// //         }
// //     }

// //     Ok(path)
// // }

// fn mnemonic_to_bip39seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
//     const BIP39_SALT_MODIFIER: &str = "mnemonic";
//     const BIP39_PBKDF2_ROUNDS: u32 = 2048;

//     let mnemonic = mnemonic.as_bytes();
//     let salt = format!("{}{}", BIP39_SALT_MODIFIER, passphrase);

//     let mut seed = [0u8; 64];
//     pbkdf2::<Hmac<Sha512>>(mnemonic, salt.as_bytes(), BIP39_PBKDF2_ROUNDS, &mut seed);
    
//     seed
// }

// pub fn bip39_to_mini_secret(phrase: &str, password: &str, language_code: Option<&str>) -> PyResult<Vec<u8>> {
// 	let salt = format!("mnemonic{}", password);

// 	let language = match Language::from_language_code(language_code.unwrap_or("en")) {
// 		Some(language) => language,
// 		None => return Err(PyValueError::new_err("Invalid language_code"))
// 	};

// 	let mnemonic = match Mnemonic::from_phrase(phrase, language) {
// 		Ok(some_mnemomic) => some_mnemomic,
// 		Err(err) => return Err(PyValueError::new_err(format!("Invalid mnemonic: {}", err.to_string())))
// 	};
// 	let mut result = [0u8; 64];

//     pbkdf2::<Hmac<Sha512>>(mnemonic.entropy(), salt.as_bytes(), 2048, &mut result);

//     Ok(result[..32].to_vec())
// }

// #[pymethods]
// impl Keypair {
//     #[new]
//     #[pyo3(signature = (
//         ss58_address = None,
//         public_key = None,
//         private_key = None,
//         ss58_format = None,
//         seed_hex = None,
//         crypto_type = 1
//     ))]
//     // fn new(
//     //     ss58_address: Option<&str>,
//     //     public_key: Option<&PyAny>,
//     //     private_key: Option<&PyAny>,
//     //     ss58_format: Option<u16>,
//     //     seed_hex: Option<&str>,
//     //     crypto_type: u8,
//     // ) -> PyResult<Self> {
//     //     let mut keypair = Keypair {
//     //         crypto_type,
//     //         seed_hex: seed_hex.map(String::from),
//     //         derive_path: None,
//     //         ss58_format,
//     //         public_key: Vec::new(),
//     //         ss58_address: None,
//     //         private_key: None,
//     //         mnemonic: None,
//     //     };

//     //     if crypto_type != 2 && ss58_address.is_some() && public_key.is_none() {
//     //         public_key = ss58_decode(ss58_address, ss58_format)
//     //     }

//     //     if let Some(pk) = private_key {
//     //         let private_key_bytes = if let Ok(s) = pk.downcast::<PyString>() {
//     //             hex::decode(s.to_str()?.trim_start_matches("0x"))?
//     //         } else if let Ok(b) = pk.downcast::<PyBytes>() {
//     //             b.as_bytes().to_vec()
//     //         } else {
//     //             return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>("private_key must be str or bytes"));
//     //         };

//     //         keypair.private_key = Some(private_key_bytes.clone());

//     //         if crypto_type == 1 {
//     //             if private_key_bytes.len() != 64 {
//     //                 return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Secret key should be 64 bytes long"));
//     //             }
//     //             if public_key.is_none() {
//     //                 public_key = public_from_secret_key(private_key_bytes)
//     //             }
//     //         }

//     //         if crypto_type == 2 {
//     //             // TODO: Implement ECDSA key handling
//     //             // private_key_obj = PrivateKey(private_key_bytes)
//     //             // public_key = private_key_obj.public_key.to_address()
//     //             // ss58_address = private_key_obj.public_key.to_checksum_address()
//     //         }
//     //     }

//     //     if public_key.is_none() {
//     //         return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("No SS58 formatted address or public key provided"));
//     //     }

//     //     let public_key_bytes = if let Some(pk) = public_key {
//     //         if let Ok(s) = pk.downcast::<PyString>() {
//     //             hex::decode(s.to_str()?.trim_start_matches("0x"))?
//     //         } else if let Ok(b) = pk.downcast::<PyBytes>() {
//     //             b.as_bytes().to_vec()
//     //         } else {
//     //             return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>("public_key must be str or bytes"));
//     //         }
//     //     } else {
//     //         Vec::new()
//     //     };

//     //     if crypto_type == 2 {
//     //         if public_key_bytes.len() != 20 {
//     //             return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Public key should be 20 bytes long"));
//     //         }
//     //     } else {
//     //         if public_key_bytes.len() != 32 {
//     //             return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Public key should be 32 bytes long"));
//     //         }

//     //         if ss58_address.is_none() {

//     //             ss58_address = ss58_encode(public_key_bytes, ss58_format)
//     //         }
//     //     }

//     //     keypair.public_key = public_key_bytes;
//     //     keypair.ss58_address = ss58_address.map(String::from);

//     //     Ok(keypair)
//     // }

//     #[staticmethod]
//     fn generate_mnemonic(words: Option<u32>) -> PyResult<String> {
//         let words = words.unwrap_or(12);
//         let language_code = language_code.unwrap_or_else(|| String::from("en"));
        
//         let mnemonic_type = match words {
//             12 => MnemonicType::Words12,
//             15 => MnemonicType::Words15,
//             18 => MnemonicType::Words18,
//             21 => MnemonicType::Words21,
//             24 => MnemonicType::Words24,
//             _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid number of words. Must be 12, 15, 18, 21, or 24.")),
//         };
//         let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
//         Ok(mnemonic.to_string());
        
//         Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>("generate_mnemonic not implemented"))
//     }

//     #[staticmethod]
//     fn validate_mnemonic(mnemonic: &str, language_code: Option<String>) -> PyResult<bool> {
//         let language_code = language_code.unwrap_or_else(|| String::from("en"));
        
//         let language = match language_code.as_str() {
//             "en" => Language::English,
//             _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unsupported language code")),
//         };
        
//         let is_valid = Mnemonic::from_phrase(mnemonic, language).is_ok();
//         Ok(is_valid)
//     }

//     #[staticmethod]
//     fn create_from_mnemonic(mnemonic: &str, ss58_format: Option<u16>, crypto_type: Option<u8>, language_code: Option<String>) -> PyResult<Keypair> {
//         let ss58_format = ss58_format.unwrap_or(42);
//         let crypto_type = crypto_type.unwrap_or(1); // Default to SR25519
//         let language_code = language_code.unwrap_or_else(|| String::from("en"));

//         if crypto_type == 2 { // ECDSA
//             if language_code != "en" {
//                 return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("ECDSA mnemonic only supports English"));
//             }


//             let private_key = mnemonic_to_ecdsa_private_key(mnemonic);
//             Keypair::create_from_private_key(private_key, None, None, Some(ss58_format), Some(crypto_type))
//         } else {
            
//             let seed_array = bip39_to_mini_secret(mnemonic, "", &language_code);
//             let seed_hex = hex::encode(&seed_array);
//             let mut keypair = Keypair::create_from_seed(&seed_hex, Some(ss58_format), Some(crypto_type))?;
//             keypair.mnemonic = Some(mnemonic.to_string());
//             Ok(keypair)
//         }

//         Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>("create_from_mnemonic not implemented"))
//     }

//     #[staticmethod]
//     fn create_from_seed(seed_hex: &str, ss58_format: Option<u16>, crypto_type: Option<u8>) -> PyResult<Keypair> {
//         let ss58_format = ss58_format.unwrap_or(42);
//         let crypto_type = crypto_type.unwrap_or(1); // Default to SR25519

//         let seed_bytes = hex::decode(seed_hex.trim_start_matches("0x"))?;

//         if crypto_type == 1 { // SR25519
            
//             let (public_key, private_key) = pair_from_seed(&seed_bytes);
//         } else if crypto_type == 0 { // ED25519
//             // TODO: Implement ed25519_zebra.ed_from_seed
//             // let (private_key, public_key) = ed25519_zebra.ed_from_seed(&seed_bytes);
//         } else {
//             return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("crypto_type '{}' not supported", crypto_type)));
//         }


//         let ss58_address = ss58_encode(&public_key, ss58_format);

//         let keypair = Keypair {
//             ss58_address: Some(ss58_address),
//             public_key: public_key,
//             private_key: Some(private_key),
//             ss58_format: Some(ss58_format),
//             crypto_type: crypto_type,
//             seed_hex: Some(seed_hex.to_string()),
//             ..Default::default()
//         };

//         Ok(keypair);

//         Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>("create_from_seed not implemented"))
//     }
// }