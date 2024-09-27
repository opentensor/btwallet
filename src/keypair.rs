use base64::decode;
use bip39::Mnemonic;
use crypto_secretbox::{ Key, KeyInit, SecretBox, XSalsa20Poly1305};
use crypto_secretbox::aead::Aead;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyObject;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, ByteArray, Encode, Pair};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EncodingExportedKeypair {
    content: Vec<String>,
    #[serde(rename = "type")]
    kind: Vec<String>,
    version: String
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct MetaExportedKeypair {
    #[serde(rename = "genesis_hash")]
    genesis_hash: Option<String>,
    name: Option<String>,
    #[serde(rename = "when_created")]
    when_created: Option<u64>
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct PolkadotJSExportedKeypair {
    encoded: String,
    encoding: EncodingExportedKeypair,
    address: Option<String>,
    meta: Option<MetaExportedKeypair>
}

const SCRYPT_LENGTH: usize = 32 + (3 * 4);
const PRIV_KEY_LEN: usize = 32;
const SCRYPT_PWD_LEN: usize = 32;
const NONCE_LENGTH: usize = 24;
const SEC_LENGTH: usize = 64;
const PKCS8_DIVIDER: [u8; 5] = [161, 35, 3, 33, 0];
const PKCS8_HEADER: [u8; 16] = [48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];

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
            // seed_hex: Some(private_key_vec.to_vec()),
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    #[staticmethod]
    pub fn create_from_encrypted_json(json_str: &str, passphrase: &str) -> PyResult<Self> {
        let json_data: PolkadotJSExportedKeypair = serde_json::from_str(json_str).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        let private_key_bytes = Keypair::decode_pair_from_encrypted_json(&json_data, passphrase).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        let private_key_str = hex::encode(private_key_bytes);
        let kp = Keypair::create_from_private_key(&private_key_str)?;
        Ok(kp)
    }

    fn decode_pair_from_encrypted_json(json_data: &PolkadotJSExportedKeypair, passphrase: &str) -> Result<Vec<u8>, PyErr> {
        if json_data.encoding.version != "3" {
            return Err(PyException::new_err("Unsupported JSON format"));
        }
        if !json_data.encoding.kind.contains(&"xsalsa20-poly1305".to_string()) {
            return Err(PyException::new_err("Unsupported encoding type"));
        }
        let mut encrypted = decode(json_data.encoded.as_bytes()).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;

        let mut password: [u8; SCRYPT_PWD_LEN] = [0; SCRYPT_PWD_LEN];
        if json_data.encoding.kind.contains(&"scrypt".to_string()) {
            let salt = &encrypted[0..32];
            let n: i32 = i32::from_le_bytes(encrypted[32..36].try_into()?);
            let p: u32 = u32::from_le_bytes(encrypted[36..40].try_into()?);
            let r: u32 = u32::from_le_bytes(encrypted[40..44].try_into()?);
            let logn: u8 = n.ilog2() as u8;
            let scrypt_params = ScryptParams::new(logn, r, p, PRIV_KEY_LEN).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
            scrypt(passphrase.as_bytes(), &salt, &scrypt_params, &mut password).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
            encrypted = encrypted[SCRYPT_LENGTH..].to_vec();
        } else {
            // password = passphrase.as_bytes().try_into()?;
            let mut passphrase_bytes: Vec<u8> = passphrase.as_bytes().to_vec();
            let diff = PRIV_KEY_LEN.saturating_sub(passphrase_bytes.len());
            passphrase_bytes.extend(std::iter::repeat(0).take(diff));
            // passphrase_bytes = std::iter::repeat(0).take(diff).extend(passphrase_bytes);
            password = <[u8; 32]>::try_from(passphrase_bytes).unwrap();
        }

        let nonce = &encrypted[0..NONCE_LENGTH];
        let message = &encrypted[NONCE_LENGTH..];
        let key: Key = password.into();
        let secret_box: XSalsa20Poly1305 = SecretBox::new(&key);
        let decrypted = secret_box.decrypt(nonce.into(), message).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        // let decrypted = secret_box.decrypt(nonce.into(), message).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        let (mut secret_key, public_key) = Keypair::decode_pkcs8(&decrypted)?;

        if json_data.encoding.content.contains(&"sr25519".to_string()) {
            let secret = schnorrkel::SecretKey::from_ed25519_bytes(&secret_key).map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
            let converted_public_key = secret.to_public();
            // assert converted_public_key key == public key
            assert_eq!(converted_public_key.to_bytes(), public_key);
            secret_key = secret.to_bytes()[..PRIV_KEY_LEN].try_into().map_err(|e| PyErr::new::<PyException, _>(e))?;
        }

        Ok(secret_key.to_vec())
    }

    fn decode_pkcs8(pkcs8: &[u8]) -> Result<([u8; PRIV_KEY_LEN], [u8; PRIV_KEY_LEN]), PyErr> {
        let pkcs8_offset = PKCS8_HEADER.len() + SEC_LENGTH;
        let private: Vec<u8> = pkcs8[PKCS8_HEADER.len()..pkcs8_offset].to_vec();
        let divider = &pkcs8[pkcs8_offset..pkcs8_offset + PKCS8_DIVIDER.len()];
        if divider != PKCS8_DIVIDER {
            return Err(PyException::new_err("Invalid pkcs8 encoding"));
        }
        let public: Vec<u8> = pkcs8[pkcs8_offset + PKCS8_DIVIDER.len()..].to_vec();
        Ok((
            private.try_into().map_err(|e| PyErr::new::<PyException, _>(e))?,
            public.try_into().map_err(|e| PyErr::new::<PyException, _>(e))?,
        ))
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
    pub fn mnemonic(&self) -> PyResult<Option<&String>> {
        if self.mnemonic.is_none() {
            Ok(None)
        } else {
            Ok(self.mnemonic.as_ref())
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
