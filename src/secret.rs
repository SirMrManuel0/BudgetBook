use zeroize::{Zeroize, Zeroizing};
use std::cmp::max;
use memsec::{mlock, munlock};

#[derive(Debug)]
pub struct Secret {
    value: Zeroizing<Vec<u8>>,
}

impl Secret {
    fn new(data: Vec<u8>) -> Self {
        let mut val = Zeroizing::new(data);
        unsafe {
            let success = mlock(val.as_mut_ptr(), val.len());
            if !success {
                panic!("mlock failed");
            }
        }
        Secret {
            value: val,
        }
    }

    fn expose(&self) -> &[u8] {
        &self.value
    }

    fn wipe(&mut self) {
        self.value.zeroize();
        unsafe {
            let success = munlock(self.value.as_mut_ptr(), self.value.len());
            if !success {
                eprintln!("munlock failed");
            }
        }
    }

}

impl Drop for Secret {
    fn drop(&mut self) {
        // redundant but explicit: ensure inner is zeroed before deallocation
        self.value.zeroize();
        unsafe {
            let _ = munlock(self.value.as_mut_ptr(), self.value.len());
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
