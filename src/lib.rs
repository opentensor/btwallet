use pyo3::prelude::*;

mod config;
mod wallet;
mod constants;
mod keypair;
mod keyfile;
mod utils;

use utils::*;

#[pymodule(name = "bittensor_wallet")]
fn bittensor_wallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<config::Config>()?;
    m.add_class::<keyfile::Keyfile>()?;
    m.add_class::<keypair::Keypair>()?;
    m.add_class::<wallet::Wallet>()?;
    m.add_function(wrap_pyfunction!(utils::is_valid_ss58_address, m)?)?;
    Ok(())
}