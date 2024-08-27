use pyo3::prelude::*;

mod keypair;
mod wallet;
use crate::keypair::*;
use sp_core::Pair;
use wallet::{Keyfile, Wallet};

#[pyfunction]
fn create_hotkey_pair(num_words: u32, name: &str) -> PyResult<PyObject> {
    // Create a new mnemonic with the specified number of words
    let mnemonic = create_mnemonic(num_words).expect("Failed to create mnemonic");
    println!("mnemonic: {:?}", mnemonic.to_string());

    // Create a hotkey pair using the mnemonic and a name.
    let (hotkey_pair, seed) = create_hotkey(mnemonic.clone(), name);

    let keypair = save_keypair(hotkey_pair, mnemonic, seed, name);

    // Convert Keypair to PyObject
    Python::with_gil(|py| {
        let keypair_dict = pyo3::types::PyDict::new_bound(py);
        keypair_dict.set_item("public_key", keypair.public_key.map(hex::encode))?;
        keypair_dict.set_item("private_key", keypair.private_key.map(hex::encode))?;
        keypair_dict.set_item("mnemonic", keypair.mnemonic)?;
        keypair_dict.set_item("seed_hex", keypair.seed_hex.map(hex::encode))?;
        keypair_dict.set_item("ss58_address", keypair.ss58_address)?;
        Ok(keypair_dict.to_object(py))
    })
}

#[pyfunction]
fn load_keypair(name: &str) -> PyResult<PyObject> {
    let keypair_data = load_keyfile_data_from_file(name).expect("Failed to load keypair");

    let keypair =
        deserialize_keyfile_data_to_keypair(&keypair_data).expect("Failed to deserialize keypair");

    Python::with_gil(|py| {
        let keypair_dict = pyo3::types::PyDict::new_bound(py);
        keypair_dict.set_item("public_key", keypair.public_key.map(hex::encode))?;
        keypair_dict.set_item("private_key", keypair.private_key.map(hex::encode))?;
        keypair_dict.set_item("mnemonic", keypair.mnemonic)?;
        keypair_dict.set_item("seed_hex", keypair.seed_hex.map(hex::encode))?;
        keypair_dict.set_item("ss58_address", keypair.ss58_address)?;
        Ok(keypair_dict.to_object(py))
    })
}
#[pyfunction]
fn verify_signature(signature: &str, message: &[u8], public_key: &str) -> PyResult<bool> {
    use sp_core::sr25519;
    use sp_core::Pair;

    let signature_bytes = hex::decode(signature).expect("Failed to decode signature");
    let public_key_bytes = hex::decode(public_key).expect("Failed to decode public key");

    let signature = sr25519::Signature::from_raw(
        signature_bytes
            .try_into()
            .expect("Invalid signature length"),
    );
    let public_key = sr25519::Public::from_raw(
        public_key_bytes
            .try_into()
            .expect("Invalid public key length"),
    );

    let verified = sr25519::Pair::verify(&signature, message, &public_key);
    Ok(verified)
}

#[pyfunction]
fn sign_message(message: &[u8], hotkey_name: &str) -> PyResult<String> {
    let keypair = load_hotkey_pair(hotkey_name).expect("Failed to load keypair");
    println!("public_key: {:?}", keypair.public());
    let signature = keypair.sign(message);

    Ok(hex::encode(signature))
}

/// A Python module implemented in Rust.
#[pymodule]
fn btwallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_hotkey_pair, m)?)?;
    m.add_function(wrap_pyfunction!(load_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;

    m.add_class::<Keyfile>()?;
    m.add_class::<Wallet>()?;

    Ok(())
}
