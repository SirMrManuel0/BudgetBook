use crate::files::errors::files_error::FilesError;

pub trait Create {
    fn create_file(path: &str) -> Result<(), FilesError>;
    fn create_folder(path: &str) -> Result<(), FilesError>;
    fn create_folders_all(path: &str) -> Result<(), FilesError>;
}

pub trait SafeCreate {
    fn safe_create_file(path: &str) -> Result<(), FilesError>;
    fn safe_create_folder(path: &str) -> Result<(), FilesError>;
    fn safe_create_folders_all(path: &str) -> Result<(), FilesError>;
}
