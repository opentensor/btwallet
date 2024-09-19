use pyo3::prelude::*;

mod config;
mod wallet;
mod constants;
mod keypair;
mod keyfile;

#[pymodule]
fn bittensor_wallet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<config::Config>()?;
    m.add_class::<keyfile::Keyfile>()?;
    m.add_class::<keypair::Keypair>()?;
    m.add_class::<wallet::Wallet>()?;
    Ok(())
}
