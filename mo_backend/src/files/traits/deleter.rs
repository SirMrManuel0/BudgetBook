use crate::files::errors::files_error::FilesError;

pub trait Deleter {
    fn delete_file(path: &str) -> Result<(), FilesError>;
}