use zeroize::Zeroize;

use crate::crypto::errors::hash::HashError;

pub trait Hash {
    fn default_hash (content: &[u8]) -> Result<Vec<u8>, HashError>;
}

pub struct DeriveData {
    pub secret: Vec<u8>,
    pub hashes: u8,
    pub salt: Option<Salt>
}

pub struct DerivedData {
    pub key: Vec<u8>,
    pub salt: Option<Vec<u8>>,
}

pub trait KeyDerivate32 {
    fn derive32 (arguments: &DeriveData) -> Result<DerivedData, HashError>;
}

impl Zeroize for DeriveData {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.hashes = 0;
        self.salt.zeroize();
    }
}

impl Zeroize for DerivedData {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
    }
}

#[derive(Clone)]
pub struct Salt {
    pub length: usize,
    pub data: Option<Vec<u8>>,
}

impl Zeroize for Salt {
    fn zeroize(&mut self) {
        self.length = 0;
        self.data.zeroize();
    }
}