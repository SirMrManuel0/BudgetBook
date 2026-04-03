use crate::files::errors::files_error::FilesError;

pub trait Deleter {
    fn delete_file(path: &str) -> Result<(), FilesError>;
    fn delete_folder(path: &str) -> Result<(), FilesError>;
    fn delete_folders_all(path: &str) -> Result<(), FilesError>;
}