use std::fs;
use std::io::ErrorKind;

use crate::files::errors::files_error::{FilesError, FilesErrorKind};
use crate::files::traits::deleter::Deleter;

pub struct DefaultFileDeleter;

impl Deleter for DefaultFileDeleter {
    fn delete_file(path: &str) -> Result<(), FilesError> {
        let mut kind: FilesErrorKind = FilesErrorKind::Unkown;
        let message = match fs::remove_file(path) {
            Ok(_) => "",
            Err(e) if e.kind() == ErrorKind::NotFound => {
                kind = FilesErrorKind::FileNotFound;
                "The files was not found."
            },
            Err(e) if e.kind() == ErrorKind::IsADirectory => {
                kind = FilesErrorKind::PathIsADirectory;
                "The given path is a directory."
            },
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                kind = FilesErrorKind::PermissionDenied;
                "The user has insufficent permissions."
            },
            Err(e) => {
                kind = FilesErrorKind::Unkown;
                "An unknown Error has occured."
            }
        };
        if message != "" {
            return Err(FilesError { kind: kind, msg: message });
        }
        Ok(())
    }
}