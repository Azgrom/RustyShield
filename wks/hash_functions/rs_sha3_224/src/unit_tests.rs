extern crate alloc;

use crate::{Sha3_224Hasher, Sha3_224State};
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let sha3_224state = Sha3_224State::default();
    let mut sha3_224hasher = sha3_224state.build_hasher();

    sha3_224hasher.write(b"");

    let output = HasherContext::finish(&mut sha3_224hasher);

    assert_eq!(format!("{output:02x}"), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
}

#[test]
fn assert_quick_fox_hash_correctness() {
    let sha3_224state = Sha3_224State::default();
    let mut sha3_224hasher = sha3_224state.build_hasher();

    sha3_224hasher.write(b"The quick brown fox jumps over the lazy dog");

    let output = HasherContext::finish(&mut sha3_224hasher);
    assert_eq!(format!("{output:02x}"), "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795")
}

#[test]
fn test() {
    let mut sha3_224hasher = Sha3_224Hasher::default();
    sha3_224hasher.write(b"your string here");

    let u64result = sha3_224hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha3_224hasher);
    assert_eq!(u64result, 0xDDF2FCD38ED7C536);
    assert_eq!(format!("{bytes_result:02x}"), "ddf2fcd38ed7c536146be476795619b9232eee08d83a94d40ebd9f79");
    assert_eq!(format!("{bytes_result:02X}"), "DDF2FCD38ED7C536146BE476795619B9232EEE08D83A94D40EBD9F79");
    assert_eq!(
        bytes_result,
        [
            0xDD, 0xF2, 0xFC, 0xD3, 0x8E, 0xD7, 0xC5, 0x36, 0x14, 0x6B, 0xE4, 0x76, 0x79, 0x56, 0x19, 0xB9, 0x23, 0x2E,
            0xEE, 0x08, 0xD8, 0x3A, 0x94, 0xD4, 0x0E, 0xBD, 0x9F, 0x79
        ]
    )
}
