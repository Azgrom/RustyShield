extern crate alloc;

use crate::{Sha256Hasher, Sha256State};
use alloc::format;
use core::hash::{BuildHasher, Hash, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn sha256_empty_string_prefix_collision_resiliency() {
    let empty_str = "";
    let default_sha256state = Sha256State::default();
    let mut prefix_free_hasher = default_sha256state.build_hasher();
    let mut sha256hasher = default_sha256state.build_hasher();

    empty_str.hash(&mut prefix_free_hasher);
    sha256hasher.write(empty_str.as_ref());

    assert_ne!(prefix_free_hasher.finish(), sha256hasher.finish());
    assert_eq!(
        format!("{:02x}", HasherContext::finish(&mut sha256hasher)),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
}

#[test]
fn sha256_quick_fox_consistency() {
    let quick_fox = "The quick brown fox jumps over the lazy dog";
    let default_sha256state = Sha256State::default();
    let mut sha256hasher = default_sha256state.build_hasher();

    sha256hasher.write(quick_fox.as_ref());

    assert_eq!(
        format!("{:02x}", HasherContext::finish(&mut sha256hasher)),
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    );
}

#[test]
fn test() {
    let mut sha256hasher = Sha256Hasher::default();
    sha256hasher.write(b"your string here");

    let u64result = sha256hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha256hasher);
    assert_eq!(u64result, 0xEBEA8483C5B21AE6);
    assert_eq!(format!("{bytes_result:02x}"), "ebea8483c5b21ae61081786be10f9704ce8975e1e5b505c03f6ab8514ecc5c0c");
    assert_eq!(format!("{bytes_result:02X}"), "EBEA8483C5B21AE61081786BE10F9704CE8975E1E5B505C03F6AB8514ECC5C0C");
    assert_eq!(
        bytes_result,
        [
            0xEB, 0xEA, 0x84, 0x83, 0xC5, 0xB2, 0x1A, 0xE6, 0x10, 0x81, 0x78, 0x6B, 0xE1, 0x0F, 0x97, 0x04, 0xCE, 0x89,
            0x75, 0xE1, 0xE5, 0xB5, 0x05, 0xC0, 0x3F, 0x6A, 0xB8, 0x51, 0x4E, 0xCC, 0x5C, 0x0C
        ]
    )
}
