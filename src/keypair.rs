use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};
use pyo3::PyObject;
use pyo3::exceptions::PyException;

use sp_core::{sr25519, Pair};
use sp_core::crypto::{Ss58Codec};

use bip39::Mnemonic;
// use hex;

#[pyclass(name = "Keypair")]
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
        Ok(
            Keypair {
                ss58_address,
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

    #[staticmethod]
    pub fn generate_mnemonic(n_words: usize) -> PyResult<String> {
        let mnemonic = Mnemonic::generate(n_words)
            .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        Ok(mnemonic.to_string())
    }

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

    // #[staticmethod]
    // pub fn create_from_seed(seed: &str) -> PyResult<Self> {
    //     let seed_bytes = hex::decode(seed.trim_start_matches("0x"))
    //         .map_err(|e| PyException::new_err(format!("Invalid hex string: {}", e)))?;
    //
    //     let pair = sr25519::Pair::from_seed_slice(&seed_bytes)
    //         .map_err(|e| PyException::new_err(format!("Failed to create pair from seed: {}", e)))?;
    //
    //     Ok(Keypair { pair })
    // }
    //
    // #[staticmethod]
    // pub fn create_from_private_key(private_key_hex: &str) -> PyResult<Self> {
    //
    //     let private_key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
    //         .map_err(|e| PyException::new_err(format!("Invalid hex string: {}", e)))?;
    //
    //     let pair = sr25519::Pair::from_seed_slice(&private_key_bytes)
    //         .map_err(|e| PyException::new_err(format!("Failed to create pair from private key: {}", e)))?;
    //     Ok(Keypair { pair })
    // }
    //
    // #[staticmethod]
    // fn create_from_uri(uri: &str) -> PyResult<Self> {
    //     let pair = Pair::from_string(uri, None)
    //         .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
    //     Ok(Keypair { pair })
    // }
    //
    // /// Returns the SS58 address
    // #[getter]
    // pub fn ss58_address(&self) -> PyResult<String> {
    //     Ok(self.pair.public().to_ss58check())
    // }
    //

    /// Returns the SS58 address
    #[getter]
    pub fn ss58_address(&self, py: Python) -> PyResult<Option<PyObject>> {
        match &self.pair {
            Some(pair) => {
                let ss58_address = pair.public().to_ss58check();
                Ok(Some(PyString::new_bound(py, &*ss58_address).into_py(py)))
            }
            None => {
                Ok(None)
            }
        }
    }

    /// Returns the public key as a bytes
    #[getter]
    pub fn public_key(&self, py: Python) -> PyResult<Option<PyObject>> {
        match &self.pair {
            Some(pair) => {
                let public_key_vec = pair.public().to_vec();
                Ok(Some(PyBytes::new_bound(py, &public_key_vec).into_py(py)))
            }
            None => {
                Ok(None)
            }
        }
    }

    /// Returns the private key as a hex string
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
    //
    // /// TODO (Roman): remove this when Wallet is ready
    // #[getter]
    // pub fn private_key(&self) -> PyResult<Option<&String>> {
    //     Ok(self.private_key.as_ref())
    // }

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
