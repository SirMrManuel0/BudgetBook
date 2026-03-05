use crate::files::errors::files_error::FilesError;

pub trait SerializableExtra {
    fn serialize(&self) -> Vec<u8>;
}

pub trait Formatter {
    fn format<T>(content: &[u8], extra: T) -> Result<Vec<u8>, FilesError>
    where 
        T: SerializableExtra;
}

pub trait FileFormatter {
    const MAGIC_BYTES: &'static [u8];
    const FILE_ENDING: &'static str;
    fn format<T>(content: &[u8], path: &str, extra: &T) -> Result<(String, Vec<u8>), FilesError>
    where 
        T: SerializableExtra;
}
