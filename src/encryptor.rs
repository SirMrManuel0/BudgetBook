use chacha20poly1305::aead::OsRng;
use pyo3::prelude::*;
use pyo3::exceptions::{PyBaseException, PyException, PyValueError};

use chacha20poly1305::{
    aead::{Aead, Payload}, XChaCha20Poly1305, XNonce, Key, KeyInit
};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use bincode;
use hkdf::Hkdf;
use sha2::Sha256;
use argon2_kdf::{Algorithm, Hasher, Hash};
use zeroize::Zeroize;
use std::str::FromStr;
use rand_core;
use rand_core::TryRngCore;

use super::secret::{SecretVault, VaultType, PyVaultType, copy_vt, Secret, ImportantTags};

/// Helper: XOR-like addition of bytes (similar to _ascii_addition_bytes in Python)
pub fn ascii_addition_bytes(inputs: &[&[u8]]) -> Vec<u8> {
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

fn has_secret_vk(en: &Encryptor, v: &VaultType) -> (bool, VaultType) { (!en.vault.get(v).is_none(), v.clone()) }

#[pyclass(dict)]
pub struct Encryptor {
    #[pyo3(get, set)]
    pub test_mode: bool,
    pub vault: SecretVault,
}

#[pymethods]
impl Encryptor {
    #[new]
    pub fn new(test: Option<bool>) -> Self {
        let test = test.unwrap_or(false);
        let mut vault: SecretVault = SecretVault::new();
        /* // In real, get system_key from OS keyring or config
        let system_key = if !test {
            // Placeholder: In production, you'd load a real base64 key from keyring
            general_purpose::STANDARD.decode("VGhpcyBpcyBhIHNlY3JldCBrZXkgZm9yIHN5c3RlbQ==").unwrap()
        } else {
            // Hardcoded test key (hex decoded)
            hex::decode("f291edbb67f5bdb73814452098436b30f8615ee01b1e086d4f747748b672355ef33481c6b4ac812f837128085ef667f00bae190c1be2b8506a2a5590a743d0ff4760d8216b4b8c0f1252fd8ad1e1332f6557874c36872b410e29a764458c12b8bd0cfe10ddc99db05b539eb4fd31880cd9704899d6a5bd69a6a3413f188f43c4d374c8c042c163074a45f987acdd69bea59beabe942468f5a5d0fcdfbbff9d4fef1a60f51247e9212da9c9b5232caa38f06e386f318e10d4b94016aa3270ad18dd68540100819bd8a0ba8e176aa601109678a4969159f767ae04d24cbd404e7b1b87721831a5af291ae257e7419200b602d9348399623e0c5380590739f83c28").unwrap()
        };

        let _ = vault.add(VaultType::SystemKey, system_key)
            .map_err(|e| PyValueError::new_err(format!("There was an error at secret creation: {:?}", e))); */

        Encryptor {
            test_mode: test,
            vault: vault,
        }
    }

    pub fn ascii_add_secrets(&mut self, store: PyRef<PyVaultType>, a: PyRef<PyVaultType>, b: PyRef<PyVaultType>) -> PyResult<()> {
        let vt_a: VaultType = {
            let (is_, vt) = has_secret_vk(&self, &a.vt);
            if !is_ {
                return Err(PyException::new_err("There is a secret missing."));
            }
            vt
        };
        let vt_b: VaultType = {
            let (is_, vt) = has_secret_vk(&self, &b.vt);
            if !is_ {
                return Err(PyException::new_err("There is a secret missing."));
            }
            vt
        };
        let store: VaultType = {
            let (is_, vt) = has_secret_vk(&self, &store.vt);
            if is_ {
                return Err(PyException::new_err("There is a secret too much."));
            }
            vt
        };
        let a: &[u8] = self.vault.get(&vt_a).expect("WTF??").expose();
        let b: &[u8] = self.vault.get(&vt_b).expect("WTF??").expose();
        let added: Vec<u8> = ascii_addition_bytes(&[a, b]);
        self.vault.add(store, added).map_err(|e| PyException::new_err(format!("Error at storing: {:?}", e)))?;
        Ok(())
    }

    pub fn add_secret(&mut self, key: PyRef<PyVaultType>, secret: &[u8], force: bool) -> PyResult<()> {
        if force {
            let (is_, vt) = has_secret_vk(&self, &key.vt);
            if is_ {
                self.vault.remove(&vt).map_err(|e| PyException::new_err(format!("Could not remove {:?}", e)))?;
            }
        }
        let vt = copy_vt(&key.vt);
        self
            .vault
            .add(vt, secret.to_vec())
            .map_err(|e| PyValueError::new_err(format!("There was an error at secret creation: {:?}", e)))?;
        Ok(())
    }

    pub fn remove_secret(&mut self, key: PyRef<PyVaultType>) -> PyResult<()> {
        let vt: VaultType = copy_vt(&key.vt);
        self.vault.remove(&vt)
            .map_err(|e| PyValueError::new_err(format!("There was an error at secret ereasure: {:?}", e)))?;
        Ok(())
    }

    pub fn clear_secrets(&mut self) -> PyResult<()> {
        self.vault.wipe_all().map_err(|e| PyBaseException::new_err(format!("There was an error trying to wipe all secrets: {:?}", e)))?;
        Ok(())
    }

    pub fn encrypt_key_chacha(&mut self, key: Option<PyRef<PyVaultType>>, from: PyRef<PyVaultType>, store: PyRef<PyVaultType>, nonce: Option<&[u8]>, aad_opt: Option<&[u8]>) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let vt_store: VaultType = {
           let (is_, vt_store) = has_secret_vk(&self, &store.vt);
            if is_ {
                return Err(PyException::new_err("Too many keys at store addr."));
            }
            vt_store
        };
        let vt_from: VaultType = {
            let (is_, vt_from) = has_secret_vk(&self, &from.vt);
            if !is_ {
                return Err(PyException::new_err("Too little keys at retrieve addr."));
            }
            vt_from
        };
        
        let mut plain: Vec<u8> = self.vault.get(&vt_from).expect("WTAF?!!!!").expose().to_vec();
        let (nonce, ciphertext) = self.encrypt_chacha(plain.as_slice(), nonce, aad_opt, key).unwrap();
        plain.zeroize();
        let c: Vec<u8> = {
            let mut v = Vec::with_capacity(nonce.len() + ciphertext.len());
            v.extend(&nonce);
            v.extend(&ciphertext);
            v
        };
        let v: VaultType = copy_vt(&vt_store);
        self.vault.add(vt_store, c).map_err(|_| PyException::new_err("There was an error at storage!"))?;
        self.vault.tag(&v, ImportantTags::Safe.as_str()).map_err(|_| PyException::new_err("Could not tag."))?;
        Ok((nonce, ciphertext))
    }

    pub fn get_secret(&self, key: PyRef<PyVaultType>, insecure: bool) -> PyResult<Vec<u8>> { 
        let key = {
            let (is_, k) = has_secret_vk(&self, &key.vt);
            if !is_ {
                return Err(PyException::new_err("Secret does not exist!"));
            }
            k
        };
        if !insecure {
            let is_safe = self.vault.check_tag(&key, ImportantTags::Safe.as_str())
                .map_err(|_| PyException::new_err("Secret can not be shared in an insecure context!"))?;
            if !is_safe {
                return Err(PyException::new_err("Secret can not be shared in an insecure context!"));
            }
        }
        Ok(self.vault.get(&key).expect("WTFFF???").expose().to_vec())
    }

    /// Return: Nonce, Ciphertext as bytes
    pub fn encrypt_chacha(&mut self, plaintext: &[u8], nonce: Option<&[u8]>, aad_opt: Option<&[u8]>,
        key: Option<PyRef<PyVaultType>>) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let key: VaultType = match key {
            Some(k) => copy_vt(&k.vt),
            None => VaultType::ChaChaKey
        };
        let (is_, key_vt) = has_secret_vk(&self, &key);
        if !is_ {
            let mut new_key: Vec<u8> = [0u8; 32].to_vec();
            rand::rng().try_fill_bytes(&mut new_key).map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Key Generation error: {:?}", e)))?;
            self.vault.add(copy_vt(&key_vt), new_key)
                .map_err(|e| PyBaseException::new_err(format!("Key Generation error: {:?}", e)))?;
        }

        let key: &[u8] = self.vault.get(&key_vt).expect("impossible").expose();
        //let key: &[u8] = key;
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

    pub fn decrypt_chacha(&mut self, ciphertext: &[u8], nonce: &[u8], aad_opt: Option<&[u8]>, from: PyRef<PyVaultType>) -> PyResult<Vec<u8>> {
        let (is_, from) = has_secret_vk(&self, &from.vt);
        if !is_ {
            return Err(PyException::new_err("There is no key at this VaultType."));
        }

        let key: &[u8] = self.vault.get(&from).expect("impossible").expose();
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

    pub fn gen_static_private_key(&mut self, store: PyRef<PyVaultType>) -> PyResult<()> {
        let (is_, store) = has_secret_vk(&self, &store.vt);
        if is_ {
            return Err(PyException::new_err("Too many keys here."));
        }
        let mut secret_a = StaticSecret::random_from_rng(OsRng);
        let secret_ = bincode::serialize(&secret_a).map_err(|_| PyException::new_err("There was an error at serialization."))?;
        secret_a.zeroize();
        self.vault.add(store, secret_).map_err(|e| PyException::new_err(format!("There was an error at mlock! {:?}", e)))?;
        Ok(())
    }

    pub fn find_shared_secret(&mut self, store: PyRef<PyVaultType>,  from_a: PyRef<PyVaultType>, from_b: PyRef<PyVaultType>, is_b_pub: bool) -> PyResult<()> {
        let (is_, from_a) = has_secret_vk(&self, &from_a.vt);
        if !is_ {
            return Err(PyException::new_err("There is no key at this VaultType. a"));
        }
        let (is_, from_b) = has_secret_vk(&self, &from_b.vt);
        if !is_ {
            return Err(PyException::new_err("There is no key at this VaultType. b"));
        }
        let (is_, store) = has_secret_vk(&self, &store.vt);
        if is_ {
            return Err(PyException::new_err("There are too many keys at this VaultType."));
        }

        let pub_key_b: PublicKey = if is_b_pub {
            let bytes: &[u8] = self.vault.get(&from_b).expect("HOWWWW?????!!!!").expose();
            let mut bytes: [u8; 32] = bytes.try_into().map_err(|_| PyException::new_err("Somehow too short."))?;
            let pub_ = PublicKey::from(bytes);
            bytes.zeroize();
            pub_
        } else {
            let priv_: &[u8] = self.vault.get(&from_b).expect("WTAF?!").expose();
            let priv_: StaticSecret = bincode::deserialize(priv_).map_err(|e| PyException::new_err(format!("Deserilization failed: {:?}", e)))?;
            PublicKey::from(&priv_)
        };
        
        let priv_key_a: StaticSecret = match self.vault.get(&from_a) {
            Some(k) => {
                let s: StaticSecret = bincode::deserialize(k.expose()).map_err(|e| PyException::new_err(format!("Failed to deserialize {:?}", e)))?;
                s
            }
            None => {
                panic!("WTF ARE YOU DOING?????");
            }
        };

        let shared_secret: SharedSecret = priv_key_a.diffie_hellman(&pub_key_b);

        self.vault.add(store, shared_secret.to_bytes().to_vec()).map_err(|_| PyException::new_err("mlock failed!"))?;

        Ok(())
    }

    pub fn derive_key(&mut self, store: PyRef<PyVaultType>, from: PyRef<PyVaultType>, salt: Option<&[u8]>) -> PyResult<()> {
        let (is_, store): (bool, VaultType) = has_secret_vk(&self, &store.vt);
        if is_ {
            return Err(PyException::new_err("Too many keys with this VaultType associated."));
        }
        let (is_, from): (bool, VaultType) = has_secret_vk(&self, &from.vt);
        if !is_ {
            return Err(PyException::new_err("No keys with this VaultType associated."));
        }
        let key: &[u8] = match self.vault.get(&from) {
            Some(k) => k.expose(),
            None => panic!("WTF HOW????")
        };
        let hk = Hkdf::<Sha256>::new(salt, key);
        let mut output: Vec<u8> = vec![0u8; 32];

        hk.expand(b"", &mut output).map_err(|_| PyException::new_err("Key derivation failed!"))?;

        self.vault.add(store, output).map_err(|_| PyException::new_err("mlock probably failed!"))?;

        Ok(())
    }

    pub fn hash_pw(&self, from: PyRef<PyVaultType>, hash_len: Option<u32>, salt_len: Option<u32>, salt: Option<&[u8]>) -> PyResult<String>{
        let (is_, vk) = has_secret_vk(self, &from.vt);
        if !is_ {
            return Err(PyException::new_err("There is no key..."));
        }
        let hash_len: u32 = hash_len.unwrap_or(64);
        let t_cost: u32 = 3;
        let p_cost: u32 = 3;
        let m_cost: u32 = 65536;
        let salt_len: u32 = salt_len.unwrap_or(16);

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
        let data: &[u8] = match self.vault.get(&vk) {
            Some(s) => s.expose(),
            None => panic!("Once again ... WTF?!")
        };
        let hash = hasher.hash(data).unwrap();
        Ok(hash.to_string())
    }

    pub fn is_eq_argon(&self, from: PyRef<PyVaultType>, hash: &str) -> PyResult<bool>{
        let vt: VaultType = {
            let (is_, secret_) = has_secret_vk(&self, &from.vt);
            if !is_ {
                return Err(PyException::new_err("There is nothing to test the hash with..."));
            }
            secret_
        };
        let data: &[u8] = self.vault.get(&vt).expect("IMPOSSIBLE!!!").expose();
        let hash = Hash::from_str(hash).unwrap();
        Ok(hash.verify(data))
    }

    pub fn show_all_keys(&self) -> PyResult<Vec<String>> {
        Ok(self.vault.show_all_keys())
    }

    pub fn compare_secrets(&self, a: PyRef<PyVaultType>, b: PyRef<PyVaultType>) -> PyResult<bool> {
        let vt_a: VaultType = {
            let (is_, vt) = has_secret_vk(&self, &a.vt);
            if !is_ {
                return Err(PyException::new_err("There is a missing secret."));
            }
            vt
        };
        let vt_b: VaultType = {
            let (is_, vt) = has_secret_vk(&self, &b.vt);
            if !is_ {
                return Err(PyException::new_err("There is a missing secret."));
            }
            vt
        };

        let sec_a: &Secret = self.vault.get(&vt_a).expect("WTF ARE YOU ACTUALLY DOING???");
        let sec_b: &Secret = self.vault.get(&vt_b).expect("WTF ARE YOU ACTUALLY DOING???");

        Ok(sec_a == sec_b)
    }
}