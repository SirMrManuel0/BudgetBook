use pyo3::prelude::*;

mod encryptor;
pub mod secret;

#[pymodule]
fn mfence(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<encryptor::Encryptor>()?;
    Ok(())
}
