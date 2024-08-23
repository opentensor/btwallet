use pyo3::prelude::*;

mod keypair;

use crate::keypair::*;
use sp_core::Pair;

/// Creates a new hotkey pair and demonstrates its functionality.
///
/// This function performs the following steps:
/// 1. Generates a mnemonic phrase.
/// 2. Creates a new hotkey pair using the mnemonic.
/// 3. Signs a test message with the hotkey.
/// 4. Verifies the signature.
/// 5. Returns the public key of the hotkey as a string.
///
/// # Returns
///
/// Returns a `PyResult<String>` containing the public key of the created hotkey.
///
/// # Errors
///
/// This function will return an error if:
/// - The mnemonic creation fails.
/// - Any of the cryptographic operations fail.
#[pyfunction]
fn create_hotkey_pub() -> PyResult<String> {
    // Create a new mnemonic with 12 words
    let mnemonic = create_mnemonic(12).expect("Failed to create mnemonic");
    println!("mnemonic: {:?}", mnemonic.to_string());

    // Create a hotkey pair using the mnemonic and a name.
    let hotkey_pair = create_hotkey(mnemonic, "name");
    println!("Hotkey pair: {:?}", hotkey_pair.public());

    // Test message
    let message = b"Hello, Opentensor!";

    // Sign the message using the hotkey pair
    let signature = hotkey_pair.sign(message);
    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("Signature: {:?}", signature);

    // Verify the signature
    let is_valid = sp_core::sr25519::Pair::verify(&signature, message, &hotkey_pair.public());
    println!("Is signature valid? {}", is_valid);

    // Extract the public key from the hotkey pair
    let pub_key = hotkey_pair.public();
    // Return the public key as a string
    Ok(pub_key.to_string())
}

/// A Python module implemented in Rust.
#[pymodule]
fn btwallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_hotkey_pub, m)?)?;

    Ok(())
}
