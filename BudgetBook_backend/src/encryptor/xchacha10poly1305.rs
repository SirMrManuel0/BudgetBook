use crate::encryptor::traits::{EnDecrypt, Encrypt, Decrypt, EncryptedData};
use crate::encryptor::errors::{EncryptorError, DecryptionFailure, EncryptionFailure};

use chacha20poly1305;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use generic_array::GenericArray;
use zeroize::Zeroize;

pub struct XChaCha20Poly1305;

impl Encrypt for XChaCha20Poly1305{
    fn encrypt(plaintext: &[u8], key: Option<&[u8]>, nonce: Option<&[u8]>) -> Result<EncryptedData, EncryptorError> {
        let mut key: Vec<u8> = match key {
            Some(k) => k.to_vec(),
            None => chacha20poly1305::XChaCha20Poly1305::generate_key(&mut OsRng).to_vec()
        };
        let key_slice_result: Result<[u8; 32], _> = key.as_slice().try_into();
        let mut key_array_non_generic: [u8; 32];
        match key_slice_result {
            Ok(arr) => { key_array_non_generic = arr; },
            Err(_) => { 
                return Err(EncryptorError::InvalidEncryption{
                    algorithm: "XChaCha20-Poly1305",
                    reason: EncryptionFailure::InvalidKey
                });
             }
        }
        let mut key_array = GenericArray::from(key_array_non_generic);
        key_array_non_generic.zeroize();
        key.zeroize();
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(&key_array);

        let mut nonce_vector: Vec<u8> = match nonce {
            Some(n) => n.to_vec(),
            None => chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut OsRng).to_vec()
        };
        let nonce_slice_result: Result<[u8; 24], _> = nonce_vector.as_slice().try_into();
        let nonce = match nonce_slice_result {
            Ok(n) => GenericArray::from(n),
            Err(_) => { 
                return Err(EncryptorError::InvalidEncryption{
                    algorithm: "XChaCha20-Poly1305",
                    reason: EncryptionFailure::InvalidNonce
                });
             }
        };
        nonce_vector.zeroize();

        let ciphertext: Vec<u8> = match cipher.encrypt(&nonce, plaintext) {
            Ok(c) => c,
            Err(_) => {
                return Err(EncryptorError::InvalidEncryption { 
                    algorithm: "XChaCha20-Poly1305", 
                    reason: EncryptionFailure::AuthenticationFailed, 
                });
            }
        };
        let key_vec: Vec<u8> = key_array.to_vec();
        key_array.zeroize();
        Ok(EncryptedData { ciphertext: ciphertext, nonce: nonce.to_vec(), key: key_vec })
    }
}

impl Decrypt for XChaCha20Poly1305 {
    fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptorError> {
        let key_slice_result: Result<[u8; 32], _> = key.try_into();
        let mut key_array_non_generic: [u8; 32];
        match key_slice_result {
            Ok(arr) => { key_array_non_generic = arr; },
            Err(_) => { 
                return Err(EncryptorError::InvalidDecryption{
                    algorithm: "XChaCha20-Poly1305",
                    reason: DecryptionFailure::InvalidKey
                });
             }
        }
        let mut key_array = GenericArray::from(key_array_non_generic);
        key_array_non_generic.zeroize();

        let nonce_slice_result: Result<[u8; 24], _> = nonce.try_into();
        let nonce = match nonce_slice_result {
            Ok(n) => GenericArray::from(n),
            Err(_) => { 
                return Err(EncryptorError::InvalidDecryption{
                    algorithm: "XChaCha20-Poly1305",
                    reason: DecryptionFailure::InvalidNonce
                });
             }
        };

        let cipher = chacha20poly1305::XChaCha20Poly1305::new(&key_array);
        let cleartext = match cipher.decrypt(&nonce, ciphertext) {
            Ok(c) => c,
            Err(_) => { 
                return Err(EncryptorError::InvalidDecryption{
                    algorithm: "XChaCha20-Poly1305",
                    reason: DecryptionFailure::AuthenticationFailed
                }); 
            }
        };
        key_array.zeroize();
        
        Ok(cleartext)
    }
}

impl EnDecrypt for XChaCha20Poly1305 {}
