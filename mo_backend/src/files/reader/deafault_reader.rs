use std::fs;

use crate::files::{errors::files_error::FilesError, traits::read::Reader};

pub struct DefaultReader;

impl Reader for DefaultReader {
    fn read(path: &str) -> Result<Vec<u8>, FilesError> {
        fs::read(path).map_err(|_| FilesError::FileDoesNotExist)
    }
}