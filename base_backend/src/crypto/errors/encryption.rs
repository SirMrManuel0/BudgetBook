#[derive(Debug)]
pub enum EncryptorError {
    InvalidDecryption{
        algorithm: &'static str,
        reason: DecryptionFailure,
    },
    InvalidEncryption{
        algorithm: &'static str,
        reason: EncryptionFailure,
    },
}

#[derive(Debug)]
pub enum DecryptionFailure {
    AuthenticationFailed,
    InvalidNonce,
    InvalidKey,
}


#[derive(Debug)]
pub enum EncryptionFailure{
    AuthenticationFailed,
    InvalidNonce,
    InvalidKey,
}