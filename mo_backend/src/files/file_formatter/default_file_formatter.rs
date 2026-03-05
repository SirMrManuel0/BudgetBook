use crate::files::traits::formatter::{ FileFormatter, SerializableExtra };
use crate::files::errors::files_error::FilesError;

pub struct DefaultV1FileFormatter;

impl FileFormatter for DefaultV1FileFormatter {
    const MAGIC_BYTES: &'static [u8] = "mo_backend".as_bytes();
    const FILE_ENDING: &'static str = ".mo";
    fn format<T>(content: &[u8], path: &str, extra: &T) -> Result<(String, Vec<u8>), FilesError>
        where 
            T: SerializableExtra {
        let mut path: String = String::from(path);
        if !path.ends_with(Self::FILE_ENDING) {
            path = String::from(path) + Self::FILE_ENDING;
        }
        let mut serialized: Vec<u8> = Self::MAGIC_BYTES.to_vec();
        serialized.extend(extra.serialize());
        serialized.extend_from_slice(content);

        Ok((path, serialized))
    }
}

