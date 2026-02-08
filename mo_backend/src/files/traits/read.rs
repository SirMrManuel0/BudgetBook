use crate::files::errors::files_error::FilesError;

pub trait Reader {
    fn read(path: &str) -> Result<Vec<u8>, FilesError>;
}