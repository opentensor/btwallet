use pyo3::prelude::*;
use pyo3::types::PyDict;

mod keypair;
mod keyfile;
mod wallet;

use crate::keypair::*;
use sp_core::Pair;


/// Convert a Keypair to a PyObject
fn keypair_to_pyobject(py: Python, keypair: Keypair) -> PyResult<PyObject> {
    let keypair_dict = PyDict::new_bound(py);
    keypair_dict.set_item("public_key", keypair.public_key.map(hex::encode))?;
    keypair_dict.set_item("ss58_address", keypair.ss58_address)?;
    Ok(keypair_dict.to_object(py))
}

/// Create a new hotkey pair
#[pyfunction]
fn create_hotkey_pair(num_words: u32, name: &str) -> PyResult<PyObject> {
    let mnemonic = create_mnemonic(num_words).expect("Failed to create mnemonic");
    let (hotkey_pair, seed) = create_keypair(mnemonic.clone(), name);
    let keypair = save_keypair(hotkey_pair, mnemonic, seed, name, "hotkey", None);
    Python::with_gil(|py| keypair_to_pyobject(py, keypair))
}

/// Create a new coldkey pair
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
    Python::with_gil(|py| keypair_to_pyobject(py, keypair))
}

/// Create a new coldkey public key pair
#[pyfunction]
fn create_coldkey_pub_pair(num_words: u32, name: &str) -> PyResult<PyObject> {
    let mnemonic = create_mnemonic(num_words).expect("Failed to create mnemonic");
    let (coldkey_pair, seed) = create_keypair(mnemonic.clone(), name);
    let keypair = save_keypair(coldkey_pair, mnemonic, seed, name, "coldkeypub", None);
    Python::with_gil(|py| keypair_to_pyobject(py, keypair))
}

/// Load a hotkey keypair
// #[pyfunction]
// fn load_hotkey_keypair(name: &str) -> PyResult<PyObject> {
//     let keypair_data = get_keypair_from_file(name, "hotkey").expect("Failed to load keypair");
//     let keypair = deserialize_keyfile_data_to_keypair(&keypair_data).expect("Failed to deserialize keypair");
//     Python::with_gil(|py| keypair_to_pyobject(py, keypair))
// }

/// Load a coldkey keypair
#[pyfunction]
#[pyo3(signature = (name, password=None))]
fn load_coldkey_keypair(name: &str, password: Option<&str>) -> PyResult<PyObject> {
    let keypair = load_keypair_dict(name, "coldkey", password).expect("Failed to load keypair");
    Python::with_gil(|py| keypair_to_pyobject(py, keypair))
}

/// Load a coldkey public key
// #[pyfunction]
// fn load_coldkey_pubkey(name: &str) -> PyResult<PyObject> {
//     let keypair_data = get_keypair_from_file(name, "coldkeypub").expect("Failed to load keypair");
//     let keypair = deserialize_keyfile_data_to_keypair(&keypair_data).expect("Failed to deserialize keypair");
//     Python::with_gil(|py| keypair_to_pyobject(py, keypair))
// }

/// Verify a signature
#[pyfunction]
fn verify_signature(signature: &str, message: &[u8], public_key: &str) -> PyResult<bool> {
    use sp_core::sr25519;

    let signature_bytes = hex::decode(signature).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    let public_key_bytes = hex::decode(public_key).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let signature = sr25519::Signature::from_raw(signature_bytes.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid signature length"))?);
    let public_key = sr25519::Public::from_raw(public_key_bytes.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid public key length"))?);

    Ok(sr25519::Pair::verify(&signature, message, &public_key))
}

/// Sign a message
#[pyfunction]
fn sign_message(message: &[u8], hotkey_name: &str, mnemonic: Option<&str>) -> PyResult<String> {
    let keypair = load_keypair(hotkey_name, "hotkey", None, mnemonic).expect("Failed to load keypair");
    let signature = keypair.sign(message);
    Ok(hex::encode(signature))
}

/// Demo secret box encryption and decryption
#[pyfunction]
fn py_demo_secret_box(password: &str, plaintext: &str) -> PyResult<()> {
    let _ = secret_box_encrypt_decrypt_demo(password, plaintext);
    Ok(())
}

/// A Python module implemented in Rust.
#[pymodule]
fn btwallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_hotkey_pair, m)?)?;
    // m.add_function(wrap_pyfunction!(load_hotkey_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(load_coldkey_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(create_coldkey_pair, m)?)?;
    m.add_function(wrap_pyfunction!(create_coldkey_pub_pair, m)?)?;
    // m.add_function(wrap_pyfunction!(load_coldkey_pubkey, m)?)?;
    m.add_function(wrap_pyfunction!(py_demo_secret_box, m)?)?;
    
    Ok(())
}
