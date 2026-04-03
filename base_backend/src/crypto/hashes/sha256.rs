use sha2::{self, Digest};

use crate::crypto::traits::{
    hash::{Hash, DeriveData, DerivedData, KeyDerivate32},
};
use crate::crypto::functions::generate_salt;
use crate::crypto::errors::hash::HashError;

pub struct Sha256;

impl Hash for Sha256 {
    fn default_hash (content: &[u8]) -> Result<Vec<u8>, HashError> {
       let result = sha2::Sha256::digest(content);
       Ok(result.to_vec())

    }
}

impl KeyDerivate32 for Sha256 {
    fn derive32 (arguments: &DeriveData) -> Result<DerivedData, HashError> {
        let mut hashes: u8 = if arguments.hashes > 0 {arguments.hashes} else {1 as u8};
        match arguments.salt.clone() {
            Some(struct_salt) => {
                let length: usize = if struct_salt.length <= 0 {1} else {struct_salt.length};
                let salt: Vec<u8> = match struct_salt.data {
                    Some(s) => s,
                    None => generate_salt(length as usize),
                };
                let mut to_derive = vec!();
                to_derive.extend_from_slice(arguments.secret.as_ref());
                to_derive.extend(salt.clone());
                let mut hashed: Vec<u8> = to_derive;
                if hashes > 1 {
                    while hashes > 0 {
                        hashed = Sha256::default_hash(hashed.as_slice())?;
                        hashes = hashes - 1;
                    }
                }
                return Ok(DerivedData { key: hashed, salt: Some(salt) });
            },
            None => {
                let mut hashed: Vec<u8> = arguments.secret.clone();
                if hashes > 1 {
                    while hashes > 0 {
                        hashed = Sha256::default_hash(hashed.as_slice())?;
                        hashes = hashes - 1;
                    }
                }
                return Ok(DerivedData{
                    key: hashed,
                    salt: None,
                });
            },
        };
    }
}