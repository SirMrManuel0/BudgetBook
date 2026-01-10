use mo_backend::crypto::{
    asymmetrical::ecc::Ed25519,
    traits::verification::{Sign, VerifySignature}
};
use zeroize::Zeroize;

#[test]
fn sign_verify(){
    let msg: &[u8; 11] = b"hello world";
    let mut sig_data = match Ed25519::sign(&mo_backend::crypto::traits::verification::SignData { content: msg.to_vec(), private_key: None }) {
        Ok(s) => s,
        Err(_) => { return assert_eq!(0, 1); }
    };
    assert!(Ed25519::verify_signature(&sig_data));
    sig_data.zeroize();
}

