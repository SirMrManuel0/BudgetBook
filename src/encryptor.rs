use pyo3::prelude::*;

use chacha20poly1305::{
    aead::{Aead, Payload}, XChaCha20Poly1305, XNonce, Key, KeyInit
};

use argon2_kdf::{Algorithm, Hasher, Hash};
use std::str::FromStr;
use rand_core;
use rand_core::TryRngCore;
use base64::{engine::general_purpose, Engine as _};

/// Helper: XOR-like addition of bytes (similar to _ascii_addition_bytes in Python)
fn ascii_addition_bytes(inputs: &[&[u8]]) -> Vec<u8> {
    if inputs.is_empty() {
        return vec![];
    }

    // Find longest slice
    let max_len = inputs.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut result = vec![0u8; max_len];

    for &arg in inputs {
        if arg.is_empty() { continue; }
        let arg_len = arg.len();
        let mut n = 0usize;
        loop {
            // offset = (arg_len - 1) + n*arg_len + (n-1)*arg_len if n > 0 else 0
            let offset = if n > 0 {
                (arg_len - 1) + n * arg_len + (n - 1) * arg_len
            } else {
                0
            };
            if offset >= result.len() {
                break;
            }
            for (i, &b) in arg.iter().enumerate() {
                let idx = offset + i;
                if idx >= result.len() {
                    break;
                }
                result[idx] = result[idx].wrapping_add(b);
            }
            n += 1;
        }
    }
    result
}

#[pyclass]
pub struct Encryptor {
    test_mode: bool,
    system_key: Vec<u8>,
}

#[pymethods]
impl Encryptor {
    #[new]
    pub fn new(test: Option<bool>) -> Self {
        let test = test.unwrap_or(false);
        // In real, get system_key from OS keyring or config
        let system_key = if !test {
            // Placeholder: In production, you'd load a real base64 key from keyring
            general_purpose::STANDARD.decode("VGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIHN5c3RlbQ==").unwrap()
        } else {
            // Hardcoded test key (hex decoded)
            hex::decode("f291edbb67f5bdb73814452098436b30f8615ee01b1e086d4f747748b672355ef33481c6b4ac812f837128085ef667f00bae190c1be2b8506a2a5590a743d0ff4760d8216b4b8c0f1252fd8ad1e1332f6557874c36872b410e29a764458c12b8bd0cfe10ddc99db05b539eb4fd31880cd9704899d6a5bd69a6a3413f188f43c4d374c8c042c163074a45f987acdd69bea59beabe942468f5a5d0fcdfbbff9d4fef1a60f51247e9212da9c9b5232caa38f06e386f318e10d4b94016aa3270ad18dd68540100819bd8a0ba8e176aa601109678a4969159f767ae04d24cbd404e7b1b87721831a5af291ae257e7419200b602d9348399623e0c5380590739f83c28").unwrap()
        };

        Encryptor {
            test_mode: test,
            system_key,
        }
    }

    /// Generate username key with Argon2id, salt is optional
    /* pub fn generate_username_key(&self, py: Python, username: &[u8], salt: Option<&[u8]>) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let combined = ascii_addition_bytes(&[username, &self.system_key]);

        let salt_bytes = match salt {
            Some(s) => s.to_vec(),
            None => {
                let mut s = vec![0u8; 16]; // 128-bit salt recommended
                rand_core::OsRng.try_fill_bytes(&mut s).unwrap();
                s
            }
        };

        // Argon2id with parameters (adjust as needed)
        let params = Params::new(4096, 3, 1, Some(32))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Argon2 params error: {:?}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Create Salt from raw bytes base64 encoded
        let salt_b64 = general_purpose::STANDARD.encode(&salt_bytes);
        let salt = Salt::from_b64(&salt_b64)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Salt parse error: {:?}", e)))?;
        let buf: &mut [u8] = &mut [0; 16];
        let slice: &mut [u8] = buf;
        let salt_bytes: &[u8] = salt.decode_b64(slice).unwrap();

        let mut key = [0u8; 32];
        argon2.hash_password_into(&combined, salt_bytes, &mut key)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Argon2 error: {:?}", e)))?;

        Ok((key.to_vec(), salt_bytes.to_vec()))
    } */

    /// Encrypt username with ChaCha20Poly1305
    /* pub fn encrypt_username(
        &self,
        py: Python,
        de_username: &[u8],
        salt: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let (key, salt_bytes) = self.generate_username_key(py, de_username, salt)?;

        // nonce 12 bytes for chacha20poly1305
        let nonce_bytes = match nonce {
            Some(n) if n.len() == 12 => n.to_vec(),
            _ => {
                let mut n = vec![0u8; 12];
                rand_core::OsRng.try_fill_bytes(&mut n).unwrap();
                n
            }
        };

        let cipher = ChaCha20Poly1305::new(key.as_slice().into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, de_username)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encrypt error: {:?}", e)))?;

        // ChaCha20Poly1305 tag is appended automatically in ciphertext,
        // So no separate tag needed.

        Ok((ciphertext, nonce_bytes, vec![], salt_bytes))
    } */

    /* /// Decrypt username with ChaCha20Poly1305
    #[staticmethod]
    pub fn decrypt_username(
        py: Python,
        en_username: &[u8],
        nonce: &[u8],
        _tag: &[u8], // tag not used, but keep param for compatibility
        user_key: &[u8],
    ) -> PyResult<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(pyo3::exceptions::PyValueError::new_err("Nonce length must be 12"));
        }
        let cipher = ChaCha20Poly1305::new(user_key.into());
        let nonce = Nonce::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce, en_username)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decrypt error: {:?}", e)))?;
        Ok(plaintext)
    }

    /// Encrypt system data with ChaCha20Poly1305, nonce_len defaults to 12 (standard for chacha)
    pub fn encrypt_system_data(&self, data: &[u8], nonce_len: Option<usize>, nonce: Option<&[u8]>) -> PyResult<Vec<u8>> {
        let nonce_len = nonce_len.unwrap_or(12);
        if nonce_len != 12 {
            return Err(pyo3::exceptions::PyValueError::new_err("Nonce length for ChaCha20Poly1305 must be 12"));
        }

        let nonce_bytes = match nonce {
            Some(n) if n.len() == nonce_len => n.to_vec(),
            _ => {
                let mut n = vec![0u8; nonce_len];
                rand_core::OsRng.try_fill_bytes(&mut n).unwrap();
                n
            }
        };

        let cipher = ChaCha20Poly1305::new(self.system_key.as_slice().into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encrypt error: {:?}", e)))?;

        // Return nonce + ciphertext
        let mut result = nonce_bytes;
        result.extend(ciphertext);
        Ok(result)
    }

    /// Decrypt system data
    pub fn decrypt_system_data(&self, data: &[u8]) -> PyResult<Vec<u8>> { */
    // /*     if data.len() < 12 {
    //         return Err(pyo3::exceptions::PyValueError::new_err("Data too short for nonce"));
    //     }
    //     let (nonce_bytes, ciphertext) = data.split_at(12);
    //     let cipher = ChaCha20Poly1305::new(self.system_key.as_slice().into());
    //     let nonce = Nonce::from_slice(nonce_bytes);
    //     let plaintext = cipher.decrypt(nonce, ciphertext)
    //         .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decrypt error: {:?}", e)))?;
    //     Ok(plaintext)
    // } */

    /// Return: Nonce, Ciphertext as bytes
    #[staticmethod]
    pub fn encrypt_chacha(key: &[u8], plaintext: &[u8], nonce: Option<&[u8]>, aad_opt: Option<&[u8]>) -> PyResult<(Vec<u8>, Vec<u8>)>{
        let key = Key::from_slice(key);
        let cipher = XChaCha20Poly1305::new(key);
        let mut salt = [0u8; 24];
        rand::rng().try_fill_bytes(&mut salt).map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Nonce Generation error: {:?}", e)))?;
        let nonce_bytes: &[u8] = if let Some(value) = nonce {
            value
        } else {
            &salt
        };
        let nonce_ = XNonce::from_slice(nonce_bytes);
        let ciphertext = if let Some(aad) = aad_opt {
            cipher.encrypt(nonce_, Payload { msg: plaintext, aad })
        } else {
            cipher.encrypt(nonce_, plaintext)
        };
        let ciphertext = ciphertext.map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encryption error: {:?}", e)))?;
        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    #[staticmethod]
    pub fn decrypt_chacha(key: &[u8], ciphertext: &[u8], nonce: &[u8], aad_opt: Option<&[u8]>) -> PyResult<Vec<u8>> {
        let key = Key::from_slice(key);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce_ = XNonce::from_slice(nonce);
        let plaintext = if let Some(aad) = aad_opt {
        cipher
            .decrypt(nonce_, Payload { msg: ciphertext, aad })
    } else {
        cipher
            .decrypt(nonce_, ciphertext)
    };
        let plaintext = plaintext.map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("EncrypDecryption error: {:?}", e)))?;
        Ok(plaintext)
    }

    /// Passwords given into this function are hashed with argon2id.
    /// 
    /// The password needs to given as bytes
    /// 
    /// The length of the hash is standardised at 64 bytes, but can vary.
    /// 
    /// The function returns as bytes [[u8]] in the following order:
    /// 
    /// hash len ([2] bytes), amount of bytes of the Algorithm ([1] byte), Algorithm name ([8] bytes (could vary)),
    /// the version ([1] byte), memory_cost ([4] bytes), time_cost ([4] bytes), parallelism ([4] bytes), length of salt ([2] byte), salt ([varying] bytes), hash ([varying] bytes)
    #[staticmethod]
    pub fn hash_pw(py: Python, data: &[u8], hash_len: Option<u32>, salt: Option<&[u8]>) -> PyResult<String>{
        py.allow_threads(|| {
            let hash_len: u32 = hash_len.unwrap_or(64);
            let t_cost: u32 = 3;
            let p_cost: u32 = 3;
            let m_cost: u32 = 65536;
            let salt_len: u32 = 16;

            // Generate random salt
            let mut salt_bytes = vec![0u8; salt_len as usize];
            rand::rngs::OsRng.try_fill_bytes(&mut salt_bytes).unwrap();

            // Hash the password
            let mut hasher = Hasher::new()
                                    .algorithm(Algorithm::Argon2id)
                                    .hash_length(hash_len)
                                    .salt_length(salt_len)
                                    .memory_cost_kib(m_cost)
                                    .threads(p_cost)
                                    .iterations(t_cost);
            if let Some(value) = salt {
                hasher = hasher.custom_salt(value);
            }
            
            let hash = hasher.hash(data).unwrap();
            Ok(hash.to_string())
        })
    }

    #[staticmethod]
    pub fn is_eq_argon(data: &[u8], hash: &str) -> PyResult<bool>{
        let hash = Hash::from_str(hash).unwrap();
        Ok(hash.verify(data))
    }

}