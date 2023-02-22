use alloc::string::String;
use core::hash::Hasher;

pub trait Sha1Context: Hasher {
    fn to_hex_string(&self) -> String;
    fn to_bytes_hash(&self) -> [u8; 20];
}
