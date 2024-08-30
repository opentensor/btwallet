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
    let (hotkey_pair, seed) = create_keypair(mnemonic.clone(), name);

    let keypair = save_keypair(hotkey_pair, mnemonic, seed, name, "hotkey", None);

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
#[pyo3(signature = (num_words, name, password=None))]
fn create_coldkey_pair(num_words: u32, name: &str, password: Option<&str>) -> PyResult<PyObject> {
    let mnemonic = create_mnemonic(num_words).expect("Failed to create mnemonic");
    let (coldkey_pair, seed) = create_keypair(mnemonic.clone(), name);
    let keypair = save_keypair(
        coldkey_pair,
        mnemonic,
        seed,
        name,
        "coldkey",
        password.map(String::from),
    );

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
fn create_coldkey_pub_pair(num_words: u32, name: &str) -> PyResult<PyObject> {
    let mnemonic = create_mnemonic(num_words).expect("Failed to create mnemonic");
    let (coldkey_pair, seed) = create_keypair(mnemonic.clone(), name);
    let keypair = save_keypair(coldkey_pair, mnemonic, seed, name, "coldkeypub", None);

    Python::with_gil(|py| {
        let keypair_dict = pyo3::types::PyDict::new_bound(py);
        keypair_dict.set_item("public_key", keypair.public_key.map(hex::encode))?;
        Ok(keypair_dict.to_object(py))
    })
}

#[pyfunction]
fn load_hotkey_keypair(name: &str) -> PyResult<PyObject> {
    let keypair_data = get_keypair_from_file(name, "hotkey").expect("Failed to load keypair");

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
#[pyo3(signature = (name, password=None))]
fn load_coldkey_keypair(name: &str, password: Option<&str>) -> PyResult<PyObject> {
    let keypair = load_keypair_dict(name, "coldkey", password).expect("Failed to load keypair");

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
fn load_coldkey_pubkey(name: &str) -> PyResult<PyObject> {
    let keypair_data = get_keypair_from_file(name, "coldkeypub").expect("Failed to load keypair");

    let keypair =
        deserialize_keyfile_data_to_keypair(&keypair_data).expect("Failed to deserialize keypair");

    Python::with_gil(|py| {
        let keypair_dict = pyo3::types::PyDict::new_bound(py);
        keypair_dict.set_item("public_key", keypair.public_key.map(hex::encode))?;
        keypair_dict.set_item("ss58_address", keypair.ss58_address)?;
        keypair_dict.set_item("seed_hex", keypair.seed_hex.map(hex::encode))?;
        keypair_dict.set_item("mnemonic", keypair.mnemonic)?;
        keypair_dict.set_item("private_key", keypair.private_key.map(hex::encode))?;
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
    let keypair = load_keypair(hotkey_name, "hotkey", None).expect("Failed to load keypair");
    println!("public_key: {:?}", keypair.public());
    let signature = keypair.sign(message);

    Ok(hex::encode(signature))
}

/// A Python module implemented in Rust.
#[pymodule]
fn btwallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_hotkey_pair, m)?)?;
    m.add_function(wrap_pyfunction!(load_hotkey_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(load_coldkey_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(create_coldkey_pair, m)?)?;
    m.add_function(wrap_pyfunction!(create_coldkey_pub_pair, m)?)?;
    m.add_function(wrap_pyfunction!(load_coldkey_pubkey, m)?)?;
    m.add_class::<Keyfile>()?;
    // m.add_class::<Wallet>()?;

    Ok(())
}
