use zeroize::Zeroize;
use std::{cmp::max, collections::HashMap};
use memsec::{mlock, munlock};
use std::hash::{Hash, Hasher};

use pyo3::prelude::*;
use pyo3::basic::CompareOp;

use std::io;

#[derive(Debug)]
pub enum SecretError {
    LockFailed,
    MissingTag,
    MissingSecret,
}

pub enum ImportantTags {
    Safe,
}

impl ImportantTags {
    pub fn as_str(&self) -> String {
        match self {
            ImportantTags::Safe => String::from("safe"),
        }
    }
}

pub struct Secret {
    value: Vec<u8>,
    locked: bool,
    tags: Vec<String>,
}

impl Secret {
    pub fn new(data: Vec<u8>) -> Result<Self, SecretError> {
        let mut val = data;
        unsafe {
            if !mlock(val.as_mut_ptr(), val.len()) {
                return Err(SecretError::LockFailed);
            }
        }
        Ok(Secret { value: val, locked: true, tags: Vec::new() })
    }

    pub fn expose(&self) -> &[u8] {
        &self.value
    }

    pub fn add_tag(&mut self, tag: String) -> () {
        self.tags.push(tag);
    }

    pub fn add_tags(&mut self, tags: Vec<String>) -> () {
        for tag in tags {
            self.tags.push(tag);
        }
    }

    pub fn get_tags(&self) -> &[String] { &self.tags }

    pub fn check_for_tag(&self, tag: &String) -> bool {
        for i in 0..self.tags.len() {
            if &self.tags[i] == tag { return true; }
        }
        false
    }

    pub fn remove_tag(&mut self, tag: &String) -> Result<(), SecretError> {
        if !self.check_for_tag(tag) { return Err(SecretError::MissingTag); }
        for i in 0..self.tags.len() {
            if &self.tags[i] == tag {
                self.tags.remove(i);
                return Ok(());
            }
        }
        Err(SecretError::MissingTag)
    }

    pub fn wipe(&mut self) -> Result<(), SecretError>{
        self.value.zeroize();
        if self.locked {
            unsafe {
                if !munlock(self.value.as_mut_ptr(), self.value.capacity()) {
                    let err = io::Error::last_os_error();
                    #[cfg(windows)]
                    {
                        if let Some(158) = err.raw_os_error() {
                            // Already unlocked → ignore
                            return Ok(());
                        }
                    }
                    return Err(SecretError::LockFailed);
                }
            }
            self.locked = false;
            Ok(())
        } else {
            Ok(())
        }
    }

    pub fn force_lock(&mut self) {
        unsafe { 
            if mlock(self.value.as_mut_ptr(), self.value.capacity()) {
                self.locked = true;
            } else {
                let err = io::Error::last_os_error();
                panic!("{}", err);
            }

        }
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.value.zeroize();
        if self.locked {
            unsafe {
                let _ = munlock(self.value.as_mut_ptr(), self.value.capacity());
            }
        }
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        let ls = self.value.len();
        let lo = other.expose().len();
        let ml = max(ls, lo);
        let other_bytes: &[u8] = other.expose();
        let mut result: usize = 0;
        let mut a: usize;
        let mut b: usize;
        for i in 0..ml {
            a = self.value.get(i).copied().unwrap_or(0) as usize;
            b = other_bytes.get(i).copied().unwrap_or(0) as usize;
            
            result |= a ^ b;
        }
        
        result |= ls ^ lo;

        result == 0
    }
}

impl Eq for Secret {}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(******)") // kein Leak der echten Daten
    }
}

#[derive(Clone)]
pub enum VaultType {
    PrivateKey,
    StaticPrivateKey,
    EphPrivateKey,
    SharedSecret,
    PublicKey,
    Password,
    ChaChaKey,
    SystemKey,
    Other(String),
}

impl PartialEq for VaultType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (VaultType::PrivateKey, VaultType::PrivateKey) => true,
            (VaultType::PublicKey, VaultType::PublicKey) => true,
            (VaultType::Password, VaultType::Password) => true,
            (VaultType::ChaChaKey, VaultType::ChaChaKey) => true,
            (VaultType::SystemKey, VaultType::SystemKey) => true,
            (VaultType::StaticPrivateKey, VaultType::StaticPrivateKey) => true,
            (VaultType::EphPrivateKey, VaultType::EphPrivateKey) => true,
            (VaultType::SharedSecret, VaultType::SharedSecret) => true,
            (VaultType::Other(a), VaultType::Other(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for VaultType {}

impl Hash for VaultType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // include a discriminant so different variants with same string don't collide
        std::mem::discriminant(self).hash(state);

        if let VaultType::Other(s) = self {
            s.hash(state);
        }
    }
}

impl std::fmt::Display for VaultType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultType::PrivateKey => write!(f, "PrivateKey"),
            VaultType::PublicKey => write!(f, "PublicKey"),
            VaultType::Password => write!(f, "Password"),
            VaultType::ChaChaKey => write!(f, "ChaChaKey"),
            VaultType::SystemKey => write!(f, "SystemKey"),
            VaultType::EphPrivateKey => write!(f, "EphPrivateKey"),
            VaultType::StaticPrivateKey => write!(f, "StaticPrivateKey"),
            VaultType::SharedSecret => write!(f, "SharedSecret"),
            VaultType::Other(s) => write!(f, "Other({})", s),
        }
    }
}

pub fn copy_vt(vault: &VaultType) -> VaultType {
    match vault {
        VaultType::SystemKey => VaultType::SystemKey,
        VaultType::PrivateKey => VaultType::PrivateKey,
        VaultType::PublicKey => VaultType::PublicKey,
        VaultType::ChaChaKey => VaultType::ChaChaKey,
        VaultType::Password => VaultType::Password,
        VaultType::StaticPrivateKey => VaultType::StaticPrivateKey,
        VaultType::EphPrivateKey => VaultType::EphPrivateKey,
        VaultType::SharedSecret => VaultType::SharedSecret,
        VaultType::Other(a) => VaultType::Other(a.to_string()),
    }
}

#[pyclass]
pub struct PyVaultType {
    pub vt: VaultType,
}

#[pymethods]
impl PyVaultType {
    /// Konstruktoren für feste Varianten
    #[classattr]
    pub fn private_key() -> Self {
        PyVaultType {
            vt: VaultType::PrivateKey,
        }
    }
    #[classattr]
    pub fn public_key() -> Self {
        PyVaultType {
            vt: VaultType::PublicKey,
        }
    }
    #[classattr]
    pub fn password() -> Self {
        PyVaultType {
            vt: VaultType::Password,
        }
    }
    #[classattr]
    pub fn shared_secret() -> Self {
        PyVaultType {
            vt: VaultType::SharedSecret,
        }
    }
    #[classattr]
    pub fn chacha_key() -> Self {
        PyVaultType {
            vt: VaultType::ChaChaKey,
        }
    }
    #[classattr]
    pub fn system_key() -> Self {
        PyVaultType {
            vt: VaultType::SystemKey,
        }
    }
    #[classattr]
    pub fn static_private_key() -> Self {
        PyVaultType {
            vt: VaultType::StaticPrivateKey,
        }
    }
    #[classattr]
    pub fn eph_private_key() -> Self {
        PyVaultType {
            vt: VaultType::EphPrivateKey,
        }
    }

    /// Flexible Other-Variante
    #[new]
    pub fn new(name: &str) -> PyResult<Self> {
        match name {
            "PrivateKey" => Ok(PyVaultType { vt: VaultType::PrivateKey }),
            "PublicKey" => Ok(PyVaultType { vt: VaultType::PublicKey }),
            "Password" => Ok(PyVaultType { vt: VaultType::Password }),
            "ChaChaKey" => Ok(PyVaultType { vt: VaultType::ChaChaKey }),
            "SystemKey" => Ok(PyVaultType { vt: VaultType::SystemKey }),
            "EphPrivateKey" => Ok(PyVaultType { vt: VaultType::EphPrivateKey }),
            "StaticPrivateKey" => Ok(PyVaultType { vt: VaultType::StaticPrivateKey }),
            "SharedSecret" => Ok(PyVaultType { vt: VaultType::SharedSecret }),
            other => Ok(PyVaultType {
                vt: VaultType::Other(other.to_string()),
            }),
        }
    }

    fn __richcmp__(&self, other: PyRef<PyVaultType>, op: CompareOp) -> bool {
        let eq = self.vt == other.vt;
        Python::with_gil(|py| match op {
            CompareOp::Eq => eq,
            CompareOp::Ne => !eq,
            _ => false,
        })
    }

    fn __hash__(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        self.vt.hash(&mut h);
        h.finish()
    }

    fn __str__(&self) -> String {
        format!("{}", self.vt)
    }

    fn __repr__(&self) -> String {
        format!("VaultType({})", self.vt)
    }
}

pub struct SecretVault {
    secrets: HashMap<VaultType, Secret>
}

fn temp(v: &VaultType) -> String {
    match v {
        VaultType::PrivateKey => String::from("PrivateKey"),
        VaultType::StaticPrivateKey => String::from("StaticPrivateKey"),
        VaultType::EphPrivateKey => String::from("EphPrivateKey"),
        VaultType::SharedSecret => String::from("SharedSecret"),
        VaultType::PublicKey => String::from("PublicKey"),
        VaultType::Password => String::from("Password"),
        VaultType::ChaChaKey => String::from("ChaChaKey"),
        VaultType::SystemKey => String::from("SystemKey"),
        VaultType::Other(a) => String::from(a),
    }
}

impl SecretVault {
    /// Create an empty vault
    pub fn new() -> Self {
        SecretVault {
            secrets: HashMap::<VaultType, Secret>::new(),
        }
    }

    /// Add a secret (takes ownership)
    pub fn add(&mut self, key: VaultType, secret: Vec<u8>) -> Result<bool, SecretError>{
        let secret_res = Secret::new(secret);
        match secret_res {
            Ok(secret) => { self.secrets.insert(key, secret); Ok(true) }
            Err(e) => Err(e)
        }
        
    }

    /// Get a reference to a secret by index
    pub fn get(&self, key: &VaultType) -> Option<&Secret> {
        self.secrets.get(key)
    }

    /// Get a mutable reference to a secret by index
    pub fn get_mut(&mut self, key: &VaultType) -> Option<&mut Secret> {
        self.secrets.get_mut(key)
    }

    pub fn tag(&mut self, key: &VaultType, tag: String) -> Result<(), SecretError> {
        match self.secrets.get_mut(key) {
            Some(s) => { s.add_tag(tag); }
            None => { return Err(SecretError::MissingSecret); }
        }
        Ok(())
    }

    pub fn check_tag(&self, key: &VaultType, tag: String) -> Result<bool, SecretError> {
        match self.secrets.get(key) {
            Some(s) => { return Ok(s.check_for_tag(&tag)); }
            None => { return Err(SecretError::MissingSecret); }
        }
    } 

    /// Removes a Secret from the Vault
    pub fn remove(&mut self, key: &VaultType) -> Result<(), SecretError>{
        if let Some(mut secret) = self.secrets.remove(key) {
            match secret.wipe() {
                Ok(e) => { e }
                Err(e) => { return Err(e); }
            }
        }
        self.relock_all();
        Ok(())
    }

    pub fn relock_all(&mut self) {
        for (_key, secret) in self.secrets.iter_mut() {
            secret.force_lock();
        }
    }

    pub fn show_all_keys(&self) -> Vec<String>{
        self.secrets
            .keys()
            .map(|v| temp(v))
            .collect()
    }

    /// Wipe all contained secrets in place
    pub fn wipe_all(&mut self) -> Result<(), SecretError>{
        let keys: Vec<_> = self.secrets.keys().cloned().collect(); // collect keys to avoid borrowing issues
        for key in keys {
            self.relock_all();
            
            if let Some(secret) = self.secrets.get_mut(&key) {
                secret.wipe()?;
            }
        }
    Ok(())
    }

    /// Consume the vault and return all secrets (they are still responsible for their own wiping)
    pub fn into_inner(&self) -> &HashMap<VaultType, Secret> {
        &self.secrets
    }
}

impl Drop for SecretVault {
    fn drop(&mut self) {
        match self.wipe_all() {
            Ok(_) => {}
            Err(_) => {}
        }
        // Then they get dropped normally (their own Drop will zeroize again / munlock)
    }
}