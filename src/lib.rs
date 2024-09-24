use pyo3::prelude::*;

mod config;
mod constants;
mod keyfile;
mod keypair;
mod utils;
mod wallet;

#[pymodule(name = "bittensor_wallet")]
fn bittensor_wallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<config::Config>()?;
    m.add_class::<keyfile::Keyfile>()?;
    m.add_class::<keypair::Keypair>()?;
    m.add_class::<wallet::Wallet>()?;
    m.add_function(wrap_pyfunction!(utils::get_ss58_format, m)?)?;
    m.add_function(wrap_pyfunction!(utils::is_valid_ss58_address, m)?)?;
    m.add_function(wrap_pyfunction!(utils::is_valid_ed25519_pubkey, m)?)?;
    m.add_function(wrap_pyfunction!(
        utils::is_valid_bittensor_address_or_public_key,
        m
    )?)?;
    Ok(())
}
