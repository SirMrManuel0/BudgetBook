use zeroize::Zeroize;

use crate::crypto::errors::encryption::EncryptorError;

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key: Vec<u8>,
}

pub struct EncryptData {
    pub plaintext: Vec<u8>,
    pub key: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

pub trait Encrypt {
    fn encrypt(arguments: &EncryptData) -> Result<EncryptedData, EncryptorError>;
}

pub trait Decrypt {
    fn decrypt(arguments: &EncryptedData) -> Result<Vec<u8>, EncryptorError>;
}

pub trait EnDecrypt: Encrypt + Decrypt {}

impl Zeroize for EncryptData {
    fn zeroize(&mut self) {
        self.plaintext.zeroize();
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

impl Zeroize for EncryptedData {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
        self.key.zeroize();
    }
}