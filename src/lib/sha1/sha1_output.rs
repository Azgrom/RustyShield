use std::ops::{Deref, DerefMut};
use crate::sha1::sha1_constants::SHA1_RAW_SIZE;

#[derive(Debug)]
pub struct Sha1Output {
    hash: [u8; SHA1_RAW_SIZE as usize]
}

impl Default for Sha1Output {
    fn default() -> Self {
        Self { hash: [0; 20] }
    }
}

impl Deref for Sha1Output {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.hash
    }
}

impl DerefMut for Sha1Output {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.hash
    }
}

impl PartialEq for Sha1Output {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl PartialEq<[u8; 20]> for Sha1Output {
    fn eq(&self, other: &[u8; 20]) -> bool {
        self.hash == *other
    }
}

impl PartialEq<&str> for Sha1Output {
    fn eq(&self, other: &&str) -> bool {
        self.to_string() == *other
    }
}

impl ToString for Sha1Output {
    fn to_string(&self) -> String {
        let mut buf = String::with_capacity((4 * SHA1_RAW_SIZE) as usize);
        for u in self.iter() {
           buf.push_str(&*format!("{:02x}", u));
        }
        buf
    }
}
