use pyo3::prelude::*;
use bip39::{Mnemonic, MnemonicType, Language};

mod keypair;
pub mod sr25519;
pub mod scalecodec;

use crate::keypair::*;

#[pyfunction]
#[pyo3(signature = (mnemonic, language_code=None))]
fn validate_mnemonic(mnemonic: &str, language_code: Option<String>) -> PyResult<bool> {
    let language_code = language_code.unwrap_or_else(|| String::from("en"));
    
    let language = match language_code.as_str() {
        "en" => Language::English,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unsupported language code")),
    };
    
    let is_valid = Mnemonic::from_phrase(mnemonic, language).is_ok();
    Ok(is_valid)
}

#[pyfunction]
fn generate_mnemonic(num_words: u32) -> PyResult<String> {
    

    let mnemonic_type = match num_words {
        12 => MnemonicType::Words12,
        15 => MnemonicType::Words15,
        18 => MnemonicType::Words18,
        21 => MnemonicType::Words21,
        24 => MnemonicType::Words24,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid number of words. Must be 12, 15, 18, 21, or 24.")),
    };
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
    Ok(mnemonic.to_string())

}




/// A Python module implemented in Rust.
#[pymodule]
fn btwallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_mnemonic, m)?)?;
    m.add_function(wrap_pyfunction!(validate_mnemonic, m)?)?;
    m.add_class::<Keypair>()?;


    Ok(())
}
