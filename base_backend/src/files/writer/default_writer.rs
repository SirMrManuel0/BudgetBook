use std::fs;
use std::io::ErrorKind;

use crate::files::traits::write::Writer;
use crate::files::errors::files_error::{FilesError, FilesErrorKind};


pub struct DefaultWriter;

impl Writer for DefaultWriter {
    fn write(path: &str, content: &[u8]) -> Result<(), FilesError> {
        let kind: FilesErrorKind;
        let message: &'static str;
        match fs::write(path, content) {
            Ok(_) => { return Ok(()); },
            Err(e) => match e.kind() {
                ErrorKind::Interrupted => {
                  kind = FilesErrorKind::Interrupted;
                  message = "The reading process was interrupted.";
                },
                ErrorKind::NotFound => {
                    kind = FilesErrorKind::FileNotFound;
                    message = "The file was not found / The parent directories are missing.";
                },
                ErrorKind::PermissionDenied => {
                    kind = FilesErrorKind::PermissionDenied;
                    message = "The user has insufficient permission.";
                },
                ErrorKind::InvalidInput => {
                    kind = FilesErrorKind::InvalidInput;
                    message = "The input was malformed. Possible there was a wrong path.";
                },
                ErrorKind::WriteZero => {
                    kind = FilesErrorKind::WriteZero;
                    message = "There could not be written anything.";
                },
                _ => {
                    kind = FilesErrorKind::Unknown;
                    message = "There was an unkown error.";
                }
            }
        };
        Err(FilesError { kind: kind, msg: message })
    }
}
