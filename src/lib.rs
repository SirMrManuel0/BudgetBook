use pyo3::prelude::*;

mod encryptor;

#[pymodule]
fn mfence(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<encryptor::Encryptor>()?;
    Ok(())
}
