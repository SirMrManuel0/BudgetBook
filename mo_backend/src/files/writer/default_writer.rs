use std::fs;

use crate::files::traits::write::Writer;
use crate::files::errors::files_error::FilesError;


pub struct DefaultWriter;

impl Writer for DefaultWriter {
    fn write(path: &str, content: Vec<u8>) -> Result<(), FilesError> {
        fs::write(path, content).map_err(|_| FilesError::CouldNotWrite)?;
        Ok(())
    }
}