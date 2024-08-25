use pyo3::prelude::*;

mod keypair;
mod wallet;
use crate::keypair::*;
use sp_core::ByteArray;
use sp_core::Pair;
use wallet::{Keyfile, Wallet};

#[pyfunction]
fn create_hotkey_pair(num_words: u32, name: &str) -> PyResult<PyObject> {
    // Create a new mnemonic with the specified number of words
    let mnemonic = create_mnemonic(num_words).expect("Failed to create mnemonic");
    println!("mnemonic: {:?}", mnemonic.to_string());

    // Create a hotkey pair using the mnemonic and a name.
    let hotkey_pair = create_hotkey(mnemonic, name);

    // Convert Keypair to PyObject
    Python::with_gil(|py| {
        let keypair_dict = pyo3::types::PyDict::new_bound(py);
        keypair_dict.set_item(
            "public_key",
            hotkey_pair.public_key.map(|pk| hex::encode(pk)),
        )?;
        keypair_dict.set_item(
            "private_key",
            hotkey_pair.private_key.map(|pk| hex::encode(pk)),
        )?;
        keypair_dict.set_item("mnemonic", hotkey_pair.mnemonic)?;
        keypair_dict.set_item(
            "seed_hex",
            hotkey_pair.seed_hex.map(|seed| hex::encode(seed)),
        )?;
        keypair_dict.set_item("ss58_address", hotkey_pair.ss58_address)?;
        Ok(keypair_dict.to_object(py))
    })
}

/// A Python module implemented in Rust.
#[pymodule]
fn btwallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_hotkey_pair, m)?)?;
    m.add_class::<Keyfile>()?;
    m.add_class::<Wallet>()?;

    Ok(())
}
