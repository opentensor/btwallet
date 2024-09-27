use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyObject;

use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, ByteArray, Pair};

use base64;
use base64::{engine::general_purpose, Engine as _};
use bip39::Mnemonic;
use serde::{Deserialize, Serialize};

use sodiumoxide::crypto::secretbox::{Key, Nonce};
use sodiumoxide::crypto::secretbox;

use pkcs8::der::Decode;
use pkcs8::PrivateKeyInfo;
use scrypt::{scrypt, Params as ScryptParams};
use std::error::Error;

#[derive(Serialize, Deserialize, Debug)]
struct Encoding {
    content: Vec<String>,
    #[serde(rename = "type")]
    enc_type: Vec<String>,
    version: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Meta {
    #[serde(rename = "genesisHash")]
    genesis_hash: Option<String>,
    name: String,
    #[serde(rename = "whenCreated")]
    when_created: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonStructure {
    encoded: String,
    encoding: Encoding,
    address: String,
    meta: Meta,
}


#[derive(Clone)]
#[pyclass]
pub struct Keypair {
    ss58_address: Option<String>,
    public_key: Option<String>,
    private_key: Option<String>,
    ss58_format: u8,
    seed_hex: Option<Vec<u8>>,
    crypto_type: u8,
    mnemonic: Option<String>,
    pair: Option<sr25519::Pair>,
}

#[pymethods]
impl Keypair {
    #[new]
    #[pyo3(signature = (ss58_address = None, public_key = None, private_key = None, ss58_format = 42, seed_hex = None, crypto_type = 1))]
    pub fn new(
        ss58_address: Option<String>,
        public_key: Option<String>,
        private_key: Option<String>,
        ss58_format: u8,
        seed_hex: Option<Vec<u8>>,
        crypto_type: u8,
    ) -> PyResult<Self> {
        if crypto_type != 1 {
            return Err(PyException::new_err(format!(
                "Unsupported crypto type: {}.",
                crypto_type
            )));
        }

        let mut ss58_address_res = ss58_address.clone();
        let mut public_key_res = public_key;

        // if public_key is passed
        if let Some(public_key_str) = &public_key_res {
            let public_key_vec =
                hex::decode(public_key_str.trim_start_matches("0x")).map_err(|e| {
                    PyException::new_err(format!("Invalid `private_key` string: {}", e))
                })?;

            let public_key_array: [u8; 32] = public_key_vec
                .try_into()
                .map_err(|_| PyException::new_err("Public key must be 32 bytes long."))?;

            let public_key = sr25519::Public::from_raw(public_key_array);

            ss58_address_res = Option::from(public_key.to_ss58check());
        }

        // If ss58_address is passed, decode the public key
        if let Some(ss58_address_str) = ss58_address.clone() {
            let public_key = sr25519::Public::from_ss58check(&ss58_address_str)
                .map_err(|e| PyException::new_err(format!("Invalid SS58 address: {}", e)))?;

            public_key_res = Some(hex::encode(public_key.to_raw()));
        }

        let kp = Keypair {
            ss58_address: ss58_address_res,
            public_key: public_key_res,
            private_key,
            ss58_format,
            seed_hex,
            crypto_type,
            mnemonic: None,
            pair: None,
        };

        // If public_key is missing (ss58_address wasn't created), return an error
        if kp.public_key.is_none() {
            return Err(PyException::new_err(
                "No SS58 formatted address or public key provided.",
            ));
        }

        Ok(kp)
    }

    fn __str__(&self) -> PyResult<String> {
        match self.ss58_address()? {
            Some(address) => Ok(format!("<Keypair (address={})>", address)),
            None => Ok("<Keypair (address=None)>".to_string()),
        }
    }

    fn __repr__(&self) -> PyResult<String> {
        self.__str__()
    }

    /// Creates mnemonic from amount of words (accepted: 12, 15, 18, 21 or 24).
    #[staticmethod]
    pub fn generate_mnemonic(n_words: usize) -> PyResult<String> {
        let mnemonic =
            Mnemonic::generate(n_words).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        Ok(mnemonic.to_string())
    }

    /// Creates Keypair from a mnemonic.
    #[staticmethod]
    pub fn create_from_mnemonic(mnemonic: &str) -> PyResult<Self> {
        let (pair, seed_vec) = sr25519::Pair::from_phrase(mnemonic, None)
            .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;

        let kp = Keypair {
            mnemonic: Some(mnemonic.to_string()),
            seed_hex: Some(seed_vec.to_vec()),
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    /// Creates Keypair from a seed.
    #[staticmethod]
    pub fn create_from_seed(seed: &str) -> PyResult<Self> {
        let seed_vec = hex::decode(seed.trim_start_matches("0x")).map_err(|e| PyException::new_err(format!("Invalid hex string: {}", e)))?;

        let pair = sr25519::Pair::from_seed_slice(&seed_vec)
            .map_err(|e| PyException::new_err(format!("Failed to create pair from seed: {}", e)))?;

        let kp = Keypair {
            seed_hex: Some(seed_vec),
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    /// Creates Keypair from `private key`.
    #[staticmethod]
    pub fn create_from_private_key(private_key: &str) -> PyResult<Self> {
        let private_key_vec = hex::decode(private_key.trim_start_matches("0x"))
            .map_err(|e| PyException::new_err(format!("Invalid `private_key` string: {}", e)))?;

        let pair = sr25519::Pair::from_seed_slice(&private_key_vec).map_err(|e| {
            PyException::new_err(format!("Failed to create pair from private key: {}", e))
        })?;

        let kp = Keypair {
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    #[staticmethod]
    #[pyo3(signature = (json_data, passphrase))]
    pub fn create_from_encrypted_json(json_data: &str, passphrase: &str) -> PyResult<Keypair> {

        /// rust version of python .rjust
        fn pad_right(mut data: Vec<u8>, total_len: usize, pad_byte: u8) -> Vec<u8> {
            if data.len() < total_len {
                let pad_len = total_len - data.len();
                data.extend(vec![pad_byte; pad_len]);
            }
            data
        }

        /// Decodes a PKCS8-encoded key pair from the provided byte slice.
        /// Returns a tuple containing the private key and public key as vectors of bytes.
        fn decode_pkcs8(data: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
            let private_key_info = PrivateKeyInfo::from_der(&*data)?;
            let secret_key = private_key_info.private_key.to_vec();
            let public_key = match private_key_info.public_key {
                Some(ref key) => key.to_vec(),
                None => return Err("Public key not found.".into()),
            };
            Ok((secret_key, public_key))
        }
        
        let json_data: JsonStructure = serde_json::from_str(json_data).unwrap();

        if json_data.encoding.version != "3" {
            return Err(pyo3::exceptions::PyValueError::new_err("Unsupported JSON format"));
        }

        let mut encrypted = general_purpose::STANDARD.decode(json_data.encoded).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;

        let password = if json_data.encoding.enc_type.contains(&"scrypt".to_string()) {
            let salt = &encrypted[0..32];
            let n = u32::from_le_bytes(encrypted[32..36].try_into()?);
            let p = u32::from_le_bytes(encrypted[36..40].try_into()?);
            let r = u32::from_le_bytes(encrypted[40..44].try_into()?);
            let log_n: u8 = n.ilog2() as u8;

            let params = ScryptParams::new(log_n, r, p, 32).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
            let mut derived_key = vec![0u8; 32];
            scrypt(passphrase.as_bytes(), salt, &params, &mut derived_key).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
            encrypted = encrypted[44..].to_vec();
            derived_key
        } else {
            let mut derived_key = passphrase.as_bytes().to_vec();
            derived_key = pad_right(derived_key, 32, 0x00);
            derived_key
        };

        let nonce_bytes = &encrypted[0..24];
        let nonce = Nonce::from_slice(nonce_bytes).ok_or("Invalid nonce length").map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        let message = &encrypted[24..];

        let key = Key::from_slice(&password).ok_or(pyo3::exceptions::PyValueError::new_err("Invalid key length"))?;
        let decrypted_data = secretbox::open(message, &nonce, &key).map_err(|e| PyErr::new::<PyException, _>(e))?;
        let (private_key, public_key) = decode_pkcs8(decrypted_data).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;

        if json_data.encoding.content.contains(&"sr25519".to_string()) {
            println!(">>> Public key: {}. Private key: {}. Need to assert.", hex::encode(public_key), hex::encode(&private_key));
        }

        // Handle crypto types (sr25519, ed25519)
        let keypair = match json_data.encoding.content.iter().any(|c| c == "sr25519") {
            true => Keypair::create_from_private_key(std::str::from_utf8(&*private_key)?),
            _ => return Err(pyo3::exceptions::PyValueError::new_err("Unsupported keypair type"))
        };

        keypair
    }

    /// Creates Keypair from create_from_uri as string.
    #[staticmethod]
    pub fn create_from_uri(uri: &str) -> PyResult<Self> {
        let pair = Pair::from_string(uri, None)
            .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;

        let kp = Keypair {
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    /// Creates a signature for given data.
    pub fn sign(&self, data: PyObject, py: Python) -> PyResult<PyObject> {
        // Convert data to bytes (data can be a string, hex, or bytes)
        let data_bytes = if let Ok(s) = data.extract::<String>(py) {
            if s.starts_with("0x") {
                hex::decode(s.trim_start_matches("0x"))
                    .map_err(|e| PyException::new_err(format!("Invalid hex string: {}", e)))?
            } else {
                s.into_bytes()
            }
        } else if let Ok(bytes) = data.extract::<Vec<u8>>(py) {
            bytes
        } else {
            return Err(PyException::new_err(
                "Unsupported data format. Expected str or bytes.",
            ));
        };

        // Check if private key is exist
        let pair = self
            .pair
            .as_ref()
            .ok_or_else(|| PyException::new_err("No private key set to create signatures"))?;

        // Generate a signature depending on the type of cryptographic key
        let signature = match self.crypto_type {
            1 => {
                // SR25519
                pair.sign(&data_bytes)
            }
            _ => {
                return Err(PyException::new_err("Crypto type not supported."));
            }
        };

        // Return the signature as a Python object (bytes)
        Ok(PyBytes::new_bound(py, &signature).into_py(py))
    }

    // The same logic as in python version `substrateinterface.keypair.Keypair.verify`
    /// Verifies data with specified signature.
    pub fn verify(&self, data: PyObject, signature: PyObject, py: Python) -> PyResult<bool> {
        // Convert data to bytes (data can be a string, hex, or bytes)
        let data_bytes = if let Ok(s) = data.extract::<String>(py) {
            if s.starts_with("0x") {
                hex::decode(s.trim_start_matches("0x"))
                    .map_err(|e| PyException::new_err(format!("Invalid hex string: {:?}", e)))?
            } else {
                s.into_bytes()
            }
        } else if let Ok(bytes) = data.extract::<Vec<u8>>(py) {
            bytes
        } else {
            return Err(PyException::new_err(
                "Unsupported data format. Expected str or bytes.",
            ));
        };

        // Convert signature to bytes
        let signature_bytes = if let Ok(s) = signature.extract::<String>(py) {
            if s.starts_with("0x") {
                hex::decode(s.trim_start_matches("0x"))
                    .map_err(|e| PyException::new_err(format!("Invalid hex string: {:?}", e)))?
            } else {
                return Err(PyException::new_err(
                    "Invalid signature format. Expected hex string.",
                ));
            }
        } else if let Ok(bytes) = signature.extract::<Vec<u8>>(py) {
            bytes
        } else {
            return Err(PyException::new_err(
                "Unsupported signature format. Expected str or bytes.",
            ));
        };

        // Check if public key is exist
        let public_key = if let Some(public_key_str) = &self.public_key {
            hex::decode(public_key_str.trim_start_matches("0x")).map_err(|e| {
                PyException::new_err(format!("Invalid `public_key` string: {:?}", e))
            })?
        } else if let Some(pair) = &self.pair {
            pair.public().to_vec()
        } else {
            return Err(PyException::new_err("No public key or pair available."));
        };

        let public =
            sr25519::Public::from_raw(<[u8; 32]>::try_from(public_key).map_err(|e| {
                PyException::new_err(format!("Invalid public key length: {:?}", e))
            })?);

        // Convert signature bytes to the type expected by the verify function
        let signature = sr25519::Signature::from_slice(&signature_bytes)
            .map_err(|_| PyException::new_err("Invalid signature"))?;

        // Verify signature depending on the type of crypto key
        let verified = match self.crypto_type {
            1 => {
                // SR25519
                sr25519::Pair::verify(&signature, &data_bytes, &public)
            }
            _ => {
                return Err(PyException::new_err("Crypto type not supported"));
            }
        };

        // If not verified, try to verify with data wrapper
        if !verified {
            let wrapped_data = [b"<Bytes>", data_bytes.as_slice(), b"</Bytes>"].concat();
            let verified_wrapped = match self.crypto_type {
                1 => {
                    // SR25519
                    sr25519::Pair::verify(&signature, &wrapped_data, &public)
                }
                _ => {
                    return Err(PyException::new_err("Crypto type not supported"));
                }
            };

            Ok(verified_wrapped)
        } else {
            Ok(verified)
        }
    }
    /// Returns the SS58 address.
    #[getter]
    pub fn ss58_address(&self) -> PyResult<Option<String>> {
        match &self.pair {
            Some(pair) => {
                let ss58_address = pair.public().to_ss58check();
                Ok(Some(ss58_address))
            }
            None => {
                if self.ss58_address.is_none() {
                    Ok(None)
                } else {
                    Ok(self.ss58_address.clone())
                }
            }
        }
    }

    /// Returns the public key as a bytes.
    #[getter]
    pub fn public_key(&self, py: Python) -> PyResult<Option<PyObject>> {
        if let Some(pair) = &self.pair {
            let public_key_vec = pair.public().to_vec();
            Ok(Some(PyBytes::new_bound(py, &public_key_vec).into_py(py)))
        } else if let Some(public_key) = &self.public_key {
            let public_key_vec = hex::decode(public_key.trim_start_matches("0x"))
                .map_err(|e| PyException::new_err(format!("Invalid `public_key` string: {}", e)))?;
            Ok(Some(PyBytes::new_bound(py, &public_key_vec).into_py(py)))
        } else {
            Ok(None)
        }
    }

    /// TODO (Roman): remove this when Wallet is ready
    /// Returns the private key as a bytes.
    #[getter]
    pub fn private_key(&self, py: Python) -> PyResult<Option<PyObject>> {
        match &self.pair {
            Some(pair) => {
                let seed = pair.to_raw_vec();
                Ok(Some(PyBytes::new_bound(py, &seed).into_py(py)))
            }
            None => {
                if self.private_key.is_none() {
                    Ok(None)
                } else {
                    Ok(Some(
                        PyBytes::new_bound(py, self.private_key.as_ref().unwrap().as_bytes())
                            .into_py(py),
                    ))
                }
            }
        }
    }

    /// Returns the ss58_format as integer.
    #[getter]
    pub fn ss58_format(&self) -> PyResult<u8> {
        Ok(self.ss58_format)
    }

    /// Returns seed_hex as bytes.
    #[getter]
    pub fn seed_hex(&self, py: Python) -> PyResult<Option<PyObject>> {
        match &self.seed_hex {
            Some(seed_hex) => Ok(Some(PyBytes::new_bound(py, seed_hex).into_py(py))),
            None => Ok(None),
        }
    }

    /// Returns crypto_type key as an int.
    #[getter]
    pub fn crypto_type(&self) -> PyResult<u8> {
        Ok(self.crypto_type)
    }

    /// Returns mnemonic key as a string.
    #[getter]
    pub fn mnemonic(&self) -> PyResult<Option<String>> {
        if self.mnemonic.is_none() {
            Ok(None)
        } else {
            Ok(self.mnemonic.clone())
        }
    }
}

// Default values for Keypair
impl Default for Keypair {
    fn default() -> Self {
        Keypair {
            ss58_address: None,
            public_key: None,
            private_key: None,
            ss58_format: 42,
            seed_hex: None,
            crypto_type: 1,
            mnemonic: None,
            pair: None,
        }
    }
}
