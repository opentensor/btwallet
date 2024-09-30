use pyo3::prelude::*;

mod config;
mod constants;
mod keyfile;
mod keypair;
mod utils;
mod wallet;

// #[pymodule(name = "bittensor_wallet")]
// fn bittensor_wallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
//     // main classes
//     m.add_class::<config::Config>()?;
//     m.add_class::<keyfile::Keyfile>()?;
//     m.add_class::<keypair::Keypair>()?;
//     m.add_class::<wallet::Wallet>()?;
//     // utils
//     m.add_function(wrap_pyfunction!(utils::get_ss58_format, m)?)?;
//     m.add_function(wrap_pyfunction!(utils::is_valid_ss58_address, m)?)?;
//     m.add_function(wrap_pyfunction!(utils::is_valid_ed25519_pubkey, m)?)?;
//     m.add_function(wrap_pyfunction!(
//         utils::is_valid_bittensor_address_or_public_key,
//         m
//     )?)?;
//     // keyfile
//     m.add_function(wrap_pyfunction!(keyfile::validate_password, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::ask_password, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::serialized_keypair_to_keyfile_data, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::deserialize_keypair_from_keyfile_data, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_nacl, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_ansible, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_legacy, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::keyfile_data_encryption_method, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::legacy_encrypt_keyfile_data, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::encrypt_keyfile_data, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::decrypt_keyfile_data, m)?)?;
//     m.add_function(wrap_pyfunction!(keyfile::get_coldkey_password_from_environment, m)?)?;
//     Ok(())
// }


#[pymodule]
fn bittensor_wallet(module: &Bound<'_, PyModule>) -> PyResult<()> {
    register_keyfile_module(module)?;
    register_keypair_module(module)?;
    register_utils_module(module)?;
    register_wallet_module(module)?;
    Ok(())
}

// keyfile module with functions
fn register_keyfile_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let keyfile_module = PyModule::new_bound(main_module.py(), "keyfile")?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::serialized_keypair_to_keyfile_data, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::deserialize_keypair_from_keyfile_data, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::validate_password, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::ask_password, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_nacl, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_ansible, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted_legacy, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::keyfile_data_is_encrypted, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::keyfile_data_encryption_method, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::legacy_encrypt_keyfile_data, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::get_coldkey_password_from_environment, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::encrypt_keyfile_data, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::decrypt_keyfile_data, &keyfile_module)?)?;
    keyfile_module.add_class::<keyfile::Keyfile>()?;
    main_module.add_submodule(&keyfile_module)
}

// keypair module with functions
fn register_keypair_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let keypair_module = PyModule::new_bound(main_module.py(), "keypair")?;
    keypair_module.add_class::<keypair::Keypair>()?;
    main_module.add_submodule(&keypair_module)
}


// utils module with functions
fn register_utils_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let utils_module = PyModule::new_bound(main_module.py(), "utils")?;
    utils_module.add_function(wrap_pyfunction!(utils::get_ss58_format, &utils_module)?)?;
    utils_module.add_function(wrap_pyfunction!(utils::is_valid_ss58_address, &utils_module)?)?;
    utils_module.add_function(wrap_pyfunction!(utils::is_valid_ed25519_pubkey, &utils_module)?)?;
    utils_module.add_function(wrap_pyfunction!(utils::is_valid_bittensor_address_or_public_key, &utils_module)?)?;
    main_module.add_submodule(&utils_module)
}

// wallet module with functions
fn register_wallet_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let wallet_module = PyModule::new_bound(main_module.py(), "wallet")?;
    wallet_module.add_class::<wallet::Wallet>()?;
    main_module.add_submodule(&wallet_module)
}