use std::{fs, io::ErrorKind};

use crate::files::{errors::files_error::{FilesError, FilesErrorKind}, traits::read::Reader};

pub struct DefaultReader;

impl Reader for DefaultReader {
    fn read(path: &str) -> Result<Vec<u8>, FilesError> {
        let mut kind: FilesErrorKind = FilesErrorKind::Unkown;
        let message = match fs::read(path) {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                kind = FilesErrorKind::Interrupted;
                "The reading process was interrupted."
            },
            Err(e) if e.kind() == ErrorKind::NotFound => {
                kind = FilesErrorKind::FileNotFound;
                "The file was not found."
            },
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                kind = FilesErrorKind::PermissionDenied;
                "The user has insufficient permissions."
            },
            Err(e) => {
                kind = FilesErrorKind::Unkown;
                "There was an unkown error."
            }
        };
        Err(FilesError {kind: kind, msg: message})
    }
}