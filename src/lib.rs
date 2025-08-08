use pyo3::prelude::*;

mod encryptor;
pub mod secret;

use encryptor::Encryptor;
use secret::PyVaultType;

#[pymodule]
fn mfence(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Encryptor>()?;
    m.add_class::<PyVaultType>()?;
    Ok(())
}
