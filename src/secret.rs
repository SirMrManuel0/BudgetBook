use zeroize::Zeroize;

pub struct Secret {
    data: Option<Vec<u8>>,
}

impl Secret {
    /// Create a new Secret from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { data: Some(bytes) }
    }

    /// Reveal secret bytes (returns Option<&[u8]>)
    /// Note: returning a reference to internal bytes — use carefully!
    pub fn reveal(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    pub fn reveal_pointer(&self) -> Option<*mut [u8]> {
        *self.data
    }

    /// Erase the secret securely
    pub fn erase(&mut self) {
        if let Some(mut d) = self.data.take() {
            d.zeroize();
        }
    }

    /// Check if the secret has been erased
    pub fn is_erased(&self) -> bool {
        self.data.is_none()
    }
}
