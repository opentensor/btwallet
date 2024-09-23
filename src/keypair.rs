use pyo3::prelude::*;
use pyo3::types::{PyBytes};
use pyo3::PyObject;
use pyo3::exceptions::PyException;

use sp_core::{sr25519, Pair};
use sp_core::crypto::Ss58Codec;
use sp_core::sr25519::Public;

use bip39::Mnemonic;
use hex;


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
        let mut ss58_address_res = ss58_address;

        if let Some(public_key_str) = &public_key {
            let public_key_vec = hex::decode(public_key_str.trim_start_matches("0x"))
                .map_err(|e| PyException::new_err(format!("Invalid `private_key` string: {}", e)))?;

            let public_key = Public::from_raw(<[u8; 32]>::try_from(public_key_vec).unwrap());

            ss58_address_res = Option::from(public_key.to_ss58check());
        }

        Ok(
            Keypair {
                ss58_address: ss58_address_res,
                public_key,
                private_key,
                ss58_format,
                seed_hex,
                crypto_type,
                mnemonic: None,
                pair: None,
            }
        )
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
        let mnemonic = Mnemonic::generate(n_words)
            .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
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
        let seed_vec = hex::decode(seed.trim_start_matches("0x"))
            .map_err(|e| PyException::new_err(format!("Invalid hex string: {}", e)))?;

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

        let pair = sr25519::Pair::from_seed_slice(&private_key_vec)
            .map_err(|e| PyException::new_err(format!("Failed to create pair from private key: {}", e)))?;

        let kp = Keypair {
            // seed_hex: Some(private_key_vec.to_vec()),
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
    }

    /// Creates Keypair from create_from_uri as string.
    #[staticmethod]
    fn create_from_uri(uri: &str) -> PyResult<Self> {
        let pair = Pair::from_string(uri, None)
            .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;

        let kp = Keypair {
            pair: Some(pair),
            ..Default::default()
        };
        Ok(kp)
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
                Ok(None)
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
            Some(seed_hex) => {
                Ok(Some(PyBytes::new_bound(py, &seed_hex).into_py(py)))
            }
            None => {
                Ok(None)
            }
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
