use std::fs;
use std::io::ErrorKind;

use crate::files::errors::files_error::{FilesError, FilesErrorKind};
use crate::files::traits::deleter::Deleter;

pub struct DefaultDeleter;

impl Deleter for DefaultDeleter {
    fn delete_file(path: &str) -> Result<(), FilesError> {
        let kind: FilesErrorKind;
        let message = match fs::remove_file(path) {
            Ok(_) => { return Ok(()); },
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    kind = FilesErrorKind::FileNotFound;
                    "The files was not found."
                },
                ErrorKind::IsADirectory => {
                    kind = FilesErrorKind::PathIsADirectory;
                    "The given path is a directory."    
                },
                ErrorKind::PermissionDenied => {
                    kind = FilesErrorKind::PermissionDenied;
                    "The user has insufficent permissions."
                },
                _ => {
                    kind = FilesErrorKind::Unknown;
                    "An unknown Error has occured."
                }
            }
        };
        Err(FilesError { kind: kind, msg: message })
    }

    fn delete_folder(path: &str) -> Result<(), FilesError> {
        let kind: FilesErrorKind;
        let message = match fs::remove_dir(path) {
            Ok(_) => { return Ok(()); },
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    kind = FilesErrorKind::FolderNotFound;
                    "The folder was not found."
                },
                ErrorKind::NotADirectory => {
                    kind = FilesErrorKind::PathIsNotADirectory;
                    "The given path is not a directory."
                },
                ErrorKind::PermissionDenied => {
                    kind = FilesErrorKind::PermissionDenied;
                    "The user has insufficent permissions."
                },
                ErrorKind::DirectoryNotEmpty => {
                    kind = FilesErrorKind::DirectoryIsNotEmpty;
                    "This Folder is not empty."
                }
                _ => {
                    kind = FilesErrorKind::Unknown;
                    "An unknown Error has occured."
                }
            }
        };
        Err(FilesError { kind: kind, msg: message })
    }

    fn delete_folders_all(path: &str) -> Result<(), FilesError> {
        let kind: FilesErrorKind;
        let message = match fs::remove_dir_all(path) {
            Ok(_) => { return Ok(()); },
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    kind = FilesErrorKind::FolderNotFound;
                    "The folder was not found."
                },
                ErrorKind::NotADirectory => {
                    kind = FilesErrorKind::PathIsNotADirectory;
                    "The given path is not a directory."
                },
                ErrorKind::PermissionDenied => {
                    kind = FilesErrorKind::PermissionDenied;
                    "The user has insufficent permissions."
                },
                ErrorKind::DirectoryNotEmpty => {
                    kind = FilesErrorKind::DirectoryIsNotEmpty;
                    "This Folder is not empty."
                }
                _ => {
                    kind = FilesErrorKind::Unknown;
                    "An unknown Error has occured."
                }
            }
        };
        Err(FilesError { kind: kind, msg: message })
    }
}