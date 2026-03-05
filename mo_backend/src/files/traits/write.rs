use crate::files::errors::files_error::FilesError;
use crate::files::traits::formatter::{FileFormatter, SerializableExtra};

pub trait Writer {
    fn write(path: &str, content: &[u8]) -> Result<(), FilesError>;
}

pub trait FormatWriter {
    fn format_writer<T, A>(path: &str, content: &[u8], extra_for_format: &A) -> Result<(), FilesError>
    where
        T: FileFormatter,
        A: SerializableExtra;
}