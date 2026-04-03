use std::{fs, io::ErrorKind};

use crate::files::{errors::files_error::{FilesError, FilesErrorKind}, traits::read::Reader};

pub struct DefaultReader;

impl Reader for DefaultReader {
    fn read(path: &str) -> Result<Vec<u8>, FilesError> {
        let kind: FilesErrorKind;
        let message: &'static str;
        match fs::read(path) {
            Ok(v) => { return Ok(v); },
            Err(e) => match e.kind() {
                ErrorKind::Interrupted => {
                  kind = FilesErrorKind::Interrupted;
                  message = "The reading process was interrupted.";
                },
                ErrorKind::NotFound => {
                    kind = FilesErrorKind::FileNotFound;
                    message = "The file was not found.";
                },
                ErrorKind::PermissionDenied => {
                    kind = FilesErrorKind::PermissionDenied;
                    message = "The user has insufficient permission.";
                },
                _ => {
                    kind = FilesErrorKind::Unknown;
                    message = "There was an unkown error.";
                }
            }
        };
        Err(FilesError {kind: kind, msg: message})
    }
}