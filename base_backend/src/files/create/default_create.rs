use crate::files::traits::create::{ Create, SafeCreate };
use crate::files::errors::files_error::{ FilesError, FilesErrorKind };

use crate::files::traits::write::Writer;
use crate::files::writer::default_writer::DefaultWriter;

use std::fs;
use std::path::Path;
use std::io::ErrorKind;

pub struct DefaultCreate;

impl Create for DefaultCreate {
    fn create_file(path: &str) -> Result<(), FilesError> {
        DefaultWriter::write(path, &[0])
    }

    fn create_folder(path: &str) -> Result<(), FilesError> {
        let kind: FilesErrorKind;
        let msg: &'static str;

        match fs::create_dir(path) {
            Ok(_) => { return Ok(()); },
            Err(e) => match e.kind() {
                ErrorKind::PermissionDenied => {
                    kind = FilesErrorKind::PermissionDenied;
                    msg = "The user has insufficient permission.";
                },
                ErrorKind::AlreadyExists => {
                    kind = FilesErrorKind::FolderAlreadyExists;
                    msg = "The folder already exists.";
                },
                ErrorKind::NotFound => {
                    kind = FilesErrorKind::FolderNotFound;
                    msg = "Parent Folders are missing.";
                },
                _ => {
                    kind = FilesErrorKind::Unknown;
                    msg = "There was an unknown error.";
                }
            }
        };

        Err(FilesError { kind, msg })
    }

    fn create_folders_all(path: &str) -> Result<(), FilesError> {
        let kind: FilesErrorKind;
        let msg: &'static str;

        match fs::create_dir_all(path) {
            Ok(_) => { return Ok(()); },
            Err(e) => match e.kind() {
                ErrorKind::PermissionDenied => {
                    kind = FilesErrorKind::PermissionDenied;
                    msg = "The user has insufficient permission.";
                },
                ErrorKind::AlreadyExists => {
                    kind = FilesErrorKind::FolderAlreadyExists;
                    msg = "The folder already exists.";
                },
                ErrorKind::NotFound => {
                    kind = FilesErrorKind::FolderNotFound;
                    msg = "Parent Folders are missing.";
                },
                _ => {
                    kind = FilesErrorKind::Unknown;
                    msg = "There was an unknown error.";
                }
            }
        };

        Err(FilesError { kind, msg })
    }
}

fn check_path(path: &str) -> bool{
    Path::new(path).exists()
}

impl SafeCreate for DefaultCreate {
    fn safe_create_file(path: &str) -> Result<(), FilesError> {
        if check_path(path) { return Ok(()); }
        DefaultCreate::create_file(path)
    }

    fn safe_create_folder(path: &str) -> Result<(), FilesError> {
        if check_path(path) { return Ok(()); }
        DefaultCreate::create_folder(path)
    }

    fn safe_create_folders_all(path: &str) -> Result<(), FilesError> {
        if check_path(path) { return Ok(()); }
        DefaultCreate::create_folders_all(path)
    }
}
