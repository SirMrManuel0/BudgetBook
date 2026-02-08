#[derive(Debug)]
pub enum FilesError {
    FileDoesNotExist,
    FileAlreadyExists,
    CouldNotWrite,
    PartiallyWritten,
    FailedToWrite,
    BufferCouldNotFlush,
    FailedToOpen,
}