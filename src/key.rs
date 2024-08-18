use pyo3::prelude::*;
use blake2::{Blake2b, Digest};
use regex::Regex;

const JUNCTION_ID_LEN: usize = 32;
const RE_JUNCTION: &str = r"(\/\/?)([^/]+)";

#[pyclass]
struct DeriveJunction {
    #[pyo3(get, set)]
    chain_code: Vec<u8>,
    #[pyo3(get, set)]
    is_hard: bool,
}

#[pymethods]
impl DeriveJunction {
    #[new]
    fn new(chain_code: Vec<u8>, is_hard: bool) -> Self {
        DeriveJunction { chain_code, is_hard }
    }

    #[staticmethod]
    fn from_derive_path(path: &str, is_hard: bool) -> PyResult<Self> {
        if path.chars().all(char::is_numeric) {
            let num = path.parse::<u64>().map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            let byte_length = ((num.bits() + 7) / 8) as usize;
            let mut chain_code = num.to_le_bytes().to_vec();
            chain_code.resize(32, 0);
            Ok(DeriveJunction { chain_code, is_hard })
        } else {
            let mut hasher = Blake2b::new();
            hasher.update(path.as_bytes());
            let result = hasher.finalize();
            let chain_code = if path.len() > JUNCTION_ID_LEN {
                result[..32].to_vec()
            } else {
                let mut padded = path.as_bytes().to_vec();
                padded.resize(32, 0);
                padded
            };
            Ok(DeriveJunction { chain_code, is_hard })
        }
    }
}

#[pyfunction]
fn extract_derive_path(derive_path: &str) -> PyResult<Vec<DeriveJunction>> {
    let re = Regex::new(RE_JUNCTION).unwrap();
    let mut junctions = Vec::new();
    let mut path_check = String::new();

    for cap in re.captures_iter(derive_path) {
        let path_separator = cap.get(1).unwrap().as_str();
        let path_value = cap.get(2).unwrap().as_str();
        path_check.push_str(path_separator);
        path_check.push_str(path_value);

        let junction = DeriveJunction::from_derive_path(path_value, path_separator == "//")?;
        junctions.push(junction);
    }

    if path_check != derive_path {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Reconstructed path '{}' does not match input", path_check)
        ));
    }

    Ok(junctions)
}

#[pymodule]
fn key(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<DeriveJunction>()?;
    m.add_function(wrap_pyfunction!(extract_derive_path, m)?)?;
    Ok(())
}
