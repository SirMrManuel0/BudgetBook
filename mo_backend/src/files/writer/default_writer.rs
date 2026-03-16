use std::fs;

use crate::files::traits::write::{FormatWriter, Writer};
use crate::files::traits::formatter::{FileFormatter, SerializableExtra};
use crate::files::errors::files_error::{FilesError, FilesErrorKind};


pub struct DefaultWriter;

impl Writer for DefaultWriter {
    fn write(path: &str, content: &[u8]) -> Result<(), FilesError> {
        fs::write(path, content)
        .map_err(|_| FilesError {kind: FilesErrorKind::CouldNotWrite, msg: "There was an error in writing this file."})?;
        Ok(())
    }
}

pub struct DefaultFormatWriter;

impl FormatWriter for DefaultFormatWriter {
    fn format_writer<T, A>(path: &str, content: &[u8], extra_for_format: &A) -> Result<(), FilesError>
        where
            T: FileFormatter,
            A: SerializableExtra {
        
        let (path, formatted_content) = T::format(content, path, extra_for_format)?;
        DefaultWriter::write(&path, formatted_content.as_slice())?;
        Ok(())
    }
}
