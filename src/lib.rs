use pyo3::prelude::*;

mod config;
mod constants;
mod keyfile;
mod keypair;
mod utils;
mod wallet;

#[pymodule(name = "bittensor_wallet")]
fn bittensor_wallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // main classes
    m.add_class::<config::Config>()?;
    m.add_class::<keyfile::Keyfile>()?;
    m.add_class::<keypair::Keypair>()?;
    m.add_class::<wallet::Wallet>()?;
    // utils
    m.add_function(wrap_pyfunction!(utils::get_ss58_format, m)?)?;
    m.add_function(wrap_pyfunction!(utils::is_valid_ss58_address, m)?)?;
    m.add_function(wrap_pyfunction!(utils::is_valid_ed25519_pubkey, m)?)?;
    m.add_function(wrap_pyfunction!(utils::is_valid_bittensor_address_or_public_key, m)?)?;
    // keyfile
    m.add_function(wrap_pyfunction!(keyfile::validate_password, m)?)?;
    m.add_function(wrap_pyfunction!(keyfile::serialized_keypair_to_keyfile_data, m)?)?;
    m.add_function(wrap_pyfunction!(keyfile::deserialize_keypair_from_keyfile_data, m)?)?;
    // m.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_nacl, m)?)?;
    // m.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_ansible, m)?)?;
    // m.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_legacy, m)?)?;
    m.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted, m)?)?;
    // m.add_function(wrap_pyfunction!(keyfile::keyfile_data_encryption_method, m)?)?;
    // m.add_function(wrap_pyfunction!(keyfile::legacy_encrypt_keyfile_data, m)?)?;
    // m.add_function(wrap_pyfunction!(keyfile::encrypt_keyfile_data, m)?)?;
    m.add_function(wrap_pyfunction!(keyfile::get_coldkey_password_from_environment, m)?)?;
    // m.add_function(wrap_pyfunction!(keyfile::decrypt_keyfile_data, m)?)?;
    Ok(())
}
