use zeroize::Zeroize;

use crate::crypto::errors::verification::VerificationError;

pub struct SignatureData {
    pub private_key: Option<Vec<u8>>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
}

pub struct SignData {
    pub content: Vec<u8>,
    pub private_key: Option<Vec<u8>>
}

pub trait Sign {
    fn sign (arguments: &SignData) -> Result<SignatureData, VerificationError>;
}

pub trait VerifySignature {
    fn verify_signature (arguments: &SignatureData) -> bool;
}

pub trait Signature: Sign + VerifySignature {}


impl Zeroize for SignatureData {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
        self.public_key.zeroize();
        self.signature.zeroize();
        self.message.zeroize();
    }
}

impl Zeroize for SignData {
    fn zeroize(&mut self) {
        self.content.zeroize();
        self.private_key.zeroize();
    }
}