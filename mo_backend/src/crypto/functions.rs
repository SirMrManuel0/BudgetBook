use rand::rngs::OsRng;
use rand::TryRngCore;

use crate::crypto::errors::hash::{HashError, HashErrorEnum};

pub fn generate_salt(n: usize) -> Vec<u8> {
    let mut salt = vec![0u8; n];
    OsRng.try_fill_bytes(&mut salt).map_err(|_| HashError::FailedRng { algorithm: "Generating Salt", reason:  HashErrorEnum::FailedRng}).unwrap();
    salt
}
