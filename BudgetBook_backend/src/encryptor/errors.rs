#[derive(Debug)]
pub enum EncryptorError{
    InvalidKey,
    InvalidCharacter,
    InvalidNonce,
}