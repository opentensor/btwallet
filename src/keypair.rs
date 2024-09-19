use pyo3::prelude::*;
use sp_core::{Pair, sr25519};

use bip39::Mnemonic;
use pyo3::exceptions::PyException;
use sp_core::crypto::Ss58Codec;
use hex;


#[pyclass(name = "Keypair", get_all)]
pub struct Keypair {
    pub pair: sr25519::Pair,
}

#[pymethods]
impl Keypair {

    #[staticmethod]
    pub fn generate_mnemonic(n_words: usize) -> PyResult<String> {
        let mnemonic = Mnemonic::generate(n_words)
            .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        Ok(mnemonic.to_string())
    }

    #[staticmethod]
    pub fn create_from_mnemonic(mnemonic: &str) -> PyResult<Self> {
        let (pair, _) = Pair::from_phrase(mnemonic, None)
            .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        Ok(Keypair { pair })
    }

    #[staticmethod]
    pub fn create_from_seed(seed: &str) -> PyResult<Self> {
        let seed_bytes = hex::decode(seed.trim_start_matches("0x"))
            .map_err(|e| PyException::new_err(format!("Invalid hex string: {}", e)))?;
        let pair = sr25519::Pair::from_seed_slice(&seed_bytes)
            .map_err(|e| PyException::new_err(format!("Failed to create pair from seed: {}", e)))?;
        Ok(Keypair { pair })
    }

    #[staticmethod]
    pub fn create_from_private_key(private_key_hex: &str) -> PyResult<Self> {
        let private_key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
            .map_err(|e| PyException::new_err(format!("Invalid hex string: {}", e)))?;
        let pair = sr25519::Pair::from_seed_slice(&private_key_bytes)
            .map_err(|e| PyException::new_err(format!("Failed to create pair from private key: {}", e)))?;
        Ok(Keypair { pair })
    }

    #[staticmethod]
    fn create_from_uri(uri: &str) -> PyResult<Self> {
        let pair = Pair::from_string(uri, None)
            .map_err(|e| PyErr::new::<PyException, _>(e.to_string()))?;
        Ok(Keypair { pair })
    }

    /// Returns the SS58 address
    #[getter]
    pub fn ss58_address(&self) -> PyResult<String> {
        Ok(self.pair.public().to_ss58check())
    }

    /// Returns the public key as a Vec<u8>
    #[getter]
    pub fn public_key_vec8(&self) -> PyResult<Vec<u8>> {
        Ok(self.pair.public().to_vec())
    }

    /// Returns the public key as a hex
    #[getter]
    pub fn public_key(&self) -> PyResult<String> {
        let public_key_bytes = self.pair.public().to_vec();
        let hex_string = format!("0x{}", hex::encode(public_key_bytes));
        Ok(hex_string)
    }

    /// Returns the private key as a hex string.
    /// TODO (Roman): remove this when Wallet is ready
    #[getter]
    pub fn private_key(&self) -> PyResult<String> {
        let seed = self.pair.to_raw_vec();
        Ok(hex::encode(seed))
    }
}