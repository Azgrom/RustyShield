#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use core::hash::Hasher;

pub trait HasherContext: Hasher {
    fn to_lower_hex(&self) -> String;
    fn to_upper_hex(&self) -> String;
    fn to_bytes_hash(&self) -> Box<[u8]>;
}
