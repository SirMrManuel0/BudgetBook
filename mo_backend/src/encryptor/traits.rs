use crate::traits::Zeroize;
use crate::encryptor::errors::EncryptorError;

pub trait Secret: Zeroize {
    fn new(secret: Vec<u8>);
    fn expose(&self) -> &[u8];
    fn compare(second: &impl Secret) -> bool; // Constant time comparison
}

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key: Vec<u8>,
}


pub trait Encrypt {
    fn encrypt(plaintext: &[u8], key: Option<&[u8]>, nonce: Option<&[u8]>) -> Result<EncryptedData, EncryptorError>;
}

pub trait Decrypt {
    fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptorError>;
}

pub trait EnDecrypt: Encrypt + Decrypt {}

