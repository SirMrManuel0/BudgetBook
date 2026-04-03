use ring::{
    rand,
    signature::{self, Ed25519KeyPair, KeyPair}
};

use crate::crypto::traits::verification::{
    Sign, SignData, Signature, SignatureData, VerifySignature
};

use crate::crypto::errors::verification::{
    VerificationError,
    SignatureFailure,
};


pub struct Ed25519;

impl Sign for Ed25519 {
    fn sign (arguments: &SignData) -> Result<SignatureData, VerificationError> {
        let key_vec: Vec<u8>;
        let cloned: Option<Vec<u8>> = arguments.private_key.clone();
        let key: Ed25519KeyPair = match cloned {
            Some(k) => {
                key_vec = k.clone();
                signature::Ed25519KeyPair::from_pkcs8(k.as_ref())
                    .map_err(|_| VerificationError::InvalidSignAction { algorithm: "Ed25519", reason: SignatureFailure::KeyFailure})?
                },
            None => {
                let rng = rand::SystemRandom::new();
                let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(|_| VerificationError::InvalidSignAction { algorithm: "Ed25519", reason: SignatureFailure::KeyGenerationFailure })?;
                key_vec = pkcs8_bytes.as_ref().to_vec();
                signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
                    .map_err(|_| VerificationError::InvalidSignAction { algorithm: "Ed25519", reason: SignatureFailure::KeyFailure })?
            }
        };

        let sig: ring::signature::Signature = key.sign(arguments.content.as_ref());
        Ok(SignatureData { private_key: Some(key_vec), public_key: key.public_key().as_ref().to_vec(), signature: sig.as_ref().to_vec(), message: arguments.content.clone() })
    }
}

impl VerifySignature for Ed25519 {
    fn verify_signature (arguments: &SignatureData) -> bool {
        let peer_public_key: signature::UnparsedPublicKey<&[u8]> =
            signature::UnparsedPublicKey::new(&signature::ED25519, arguments.public_key.as_ref());
        match peer_public_key.verify(arguments.message.as_ref(), arguments.signature.as_ref()) {
            Ok(_) => return true,
            Err(_) => return false,
        }
    }
}

impl Signature for Ed25519 {}