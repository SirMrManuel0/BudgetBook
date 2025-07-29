use pyo3::prelude::*;

mod encryptor;

#[pyfunction]
fn hello_world() {
    println!("Hello, world!");
}

#[pymodule]
fn mfence(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register the hello_world function with the Python module
    m.add_function(wrap_pyfunction!(hello_world, m)?)?;
    Ok(())
}
