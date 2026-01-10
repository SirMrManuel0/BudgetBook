use mo_backend::crypto::{
    symmetrical::xchacha10poly1305::XChaCha20Poly1305,
    traits::encryption::{Encrypt, Decrypt, EncryptedData, EncryptData},
};
use zeroize::Zeroize;

#[test]
fn decrypt_round_trip() {
    let key: [u8; 32] = [0u8; 32];
    let nonce: [u8; 24] = [0u8; 24];
    let plaintext = b"hello world";
    let mut encrypt_this: EncryptData = EncryptData { plaintext: plaintext.to_vec(), key: Some(key.to_vec()), nonce: Some(nonce.to_vec()) };
    let mut encryptor_data: EncryptedData = match XChaCha20Poly1305::encrypt(&encrypt_this) {
        Ok(r) => r,
        Err(_) => { return assert_eq!(1, 0); }
    };
    let result: Vec<u8> = match XChaCha20Poly1305::decrypt(&encryptor_data) {
        Ok(r) => r,
        Err(_) => { return assert_eq!(1, 0); }
    };
    encrypt_this.zeroize();
    encryptor_data.zeroize();

    assert_eq!(plaintext, result.as_slice())
}