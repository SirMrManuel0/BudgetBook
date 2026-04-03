#[derive(Debug)]
pub struct FilesError{
    pub kind: FilesErrorKind,
    pub msg: &'static str,
}

#[derive(Debug)]
pub enum FilesErrorKind {
    FileDoesNotExist,
    FileAlreadyExists,
    CouldNotWrite,
    PartiallyWritten,
    FailedToWrite,
    BufferCouldNotFlush,
    FailedToOpen,
    FileNotFound,
    PathIsADirectory,
    PermissionDenied,
    Unknown,
    Interrupted,
    InvalidInput,
    WriteZero,
    FolderAlreadyExists,
    FolderNotFound,
    PathIsNotADirectory,
    DirectoryIsNotEmpty,
}