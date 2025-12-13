use mo_backend::encryptor::{
    xchacha10poly1305::XChaCha20Poly1305,
    traits::{Encrypt, Decrypt, EncryptedData},
};

#[test]
fn decrypt_round_trip() {
    let key: [u8; 32] = [0u8; 32];
    let nonce: [u8; 24] = [0u8; 24];
    let plaintext = b"hello world";
    let encryptor_data: EncryptedData = match XChaCha20Poly1305::encrypt(plaintext, Some(&key), Some(&nonce)) {
        Ok(r) => r,
        Err(_) => { return assert_eq!(1, 0); }
    };
    let ciphertext: &[u8] = encryptor_data.ciphertext.as_slice();
    let result: Vec<u8> = match XChaCha20Poly1305::decrypt(ciphertext, &key, &nonce) {
        Ok(r) => r,
        Err(_) => { return assert_eq!(1, 0); }
    };

    assert_eq!(plaintext, result.as_slice())
}