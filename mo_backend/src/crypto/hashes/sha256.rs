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
                let hashed: Vec<u8> = Sha256::default_hash(&to_derive)?;
                return Ok(DerivedData { key: hashed, salt: Some(salt) });
            },
            None => {
                return Ok(DerivedData{
                    key: Sha256::default_hash(&arguments.secret)?,
                    salt: None,
                });
            },
        };
    }
}