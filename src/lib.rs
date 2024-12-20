/// Main module for declaration of python package structure
use pyo3::prelude::*;
use pyo3::types::{PyTuple, PyType};
use pyo3::ffi;

mod config;
mod constants;
mod errors;
mod keyfile;
mod keypair;
mod utils;
mod wallet;

#[pymodule]
fn bittensor_wallet(py: Python<'_>,module: &Bound<'_, PyModule>) -> PyResult<()> {
    // classes to main module
    module.add_class::<config::Config>()?;
    module.add_class::<keyfile::Keyfile>()?;
    module.add_class::<keypair::Keypair>()?;
    module.add_class::<wallet::Wallet>()?;
    // submodules to main module
    register_config_module(module)?;
    register_errors_module(module)?;
    register_keyfile_module(module)?;
    register_keypair_module(py, module)?;
    register_utils_module(module)?;
    register_wallet_module(module)?;
    Ok(())
}

fn register_config_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let config_module = PyModule::new_bound(main_module.py(), "config")?;
    config_module.add_class::<config::Config>()?;
    main_module.add_submodule(&config_module)
}

fn register_errors_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let errors_module = PyModule::new_bound(main_module.py(), "errors")?;
    errors_module.add_class::<errors::ConfigurationError>()?;
    errors_module.add_class::<errors::KeyFileError>()?;
    errors_module.add_class::<errors::PasswordError>()?;
    main_module.add_submodule(&errors_module)
}

// keyfile module with functions
fn register_keyfile_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let keyfile_module = PyModule::new_bound(main_module.py(), "keyfile")?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::serialized_keypair_to_keyfile_data,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::deserialize_keypair_from_keyfile_data,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::validate_password,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(keyfile::ask_password, &keyfile_module)?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_is_encrypted_nacl,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_is_encrypted_ansible,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_is_encrypted_legacy,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_is_encrypted,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::keyfile_data_encryption_method,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::legacy_encrypt_keyfile_data,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::get_password_from_environment,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::encrypt_keyfile_data,
        &keyfile_module
    )?)?;
    keyfile_module.add_function(wrap_pyfunction!(
        keyfile::decrypt_keyfile_data,
        &keyfile_module
    )?)?;
    keyfile_module.add_class::<keyfile::Keyfile>()?;
    main_module.add_submodule(&keyfile_module)
}

// keypair module with functions
fn register_keypair_module(py: Python, main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let keypair_module = PyModule::new_bound(py, "keypair")?;

    // import python substrateinterface into the rust
    let substrate_module = py.import_bound("substrateinterface")?;
    let origin_keypair_class = substrate_module.getattr("Keypair")?;

    // defining Wallet Keypair class
    let keypair_type = PyType::new_bound::<keypair::Keypair>(py);

    // update base and mro in Wallet Keypair type
    unsafe {
        (*keypair_type.as_type_ptr()).tp_base = origin_keypair_class.as_ptr() as *mut _;

        let mro_tuple = PyTuple::new_bound(py, &[keypair_type.as_ref(), &origin_keypair_class]);
        ffi::Py_INCREF(mro_tuple.as_ptr());
        (*keypair_type.as_type_ptr()).tp_mro = mro_tuple.as_ptr() as *mut _;

        if ffi::PyType_Ready(keypair_type.as_type_ptr()) != 0 {
            return Err(PyErr::fetch(py));
        }
    }

    keypair_module.add("Keypair", keypair_type)?;
    main_module.add_submodule(&keypair_module)
}


// utils module with functions
fn register_utils_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let utils_module = PyModule::new_bound(main_module.py(), "utils")?;
    utils_module.add_function(wrap_pyfunction!(utils::get_ss58_format, &utils_module)?)?;
    utils_module.add_function(wrap_pyfunction!(
        utils::is_valid_ss58_address,
        &utils_module
    )?)?;
    utils_module.add_function(wrap_pyfunction!(
        utils::is_valid_ed25519_pubkey,
        &utils_module
    )?)?;
    utils_module.add_function(wrap_pyfunction!(
        utils::is_valid_bittensor_address_or_public_key,
        &utils_module
    )?)?;
    utils_module.add("SS58_FORMAT", utils::SS58_FORMAT)?;
    main_module.add_submodule(&utils_module)
}

// wallet module with functions
fn register_wallet_module(main_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let wallet_module = PyModule::new_bound(main_module.py(), "wallet")?;
    wallet_module.add_function(wrap_pyfunction!(
        wallet::display_mnemonic_msg,
        &wallet_module
    )?)?;
    wallet_module.add_class::<wallet::Wallet>()?;
    main_module.add_submodule(&wallet_module)
}
