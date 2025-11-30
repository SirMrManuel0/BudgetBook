pub trait Secret {
    fn new(secret: Vec<u8>);
    fn expose() -> Vec<u8>;
    fn compare(second: Secret) -> bool; // Constant time comparison
    fn zeroize();
}

pub trait Encrypt {
    fn encrypt(key: impl Secret, clear: Vec<u8>, nonce: Option<Vec<u8>>) -> Vec<Vec<u8>, Vec<u8>>;
}

pub trait Decrypt {
    fn decrypt(key: impl Secret, encrypted: Vec<u8>, nonce: Vec<u8>) -> Vec<u8>;
}

pub trait EnDecrypt: Encrypt + Decrypt {}

