use crate::files::errors::files_error::FilesError;

pub trait Writer {
    fn write(path: &str, content: Vec<u8>) -> Result<(), FilesError>;
}