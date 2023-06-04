extern crate alloc;
use crate::sha384state::Sha384State;
use crate::Sha384Hasher;
use alloc::format;
use core::hash::{BuildHasher, Hash, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn sha384_empty_string_prefix_collision_resiliency() {
    let empty_str = "";
    let default_sha256state = Sha384State::default();
    let mut prefix_free_hasher = default_sha256state.build_hasher();
    let mut prefix_hasher = default_sha256state.build_hasher();

    empty_str.hash(&mut prefix_free_hasher);
    prefix_hasher.write(empty_str.as_ref());

    assert_ne!(prefix_free_hasher.finish(), prefix_hasher.finish());
    assert_eq!(
        format!("{:02x}", HasherContext::finish(&mut prefix_hasher)),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    )
}

#[test]
fn sha384_quick_fox_consistency() {
    let quick_fox = "The quick brown fox jumps over the lazy dog";
    let default_sha256state = Sha384State::default();
    let mut sha384hasher = default_sha256state.build_hasher();

    sha384hasher.write(quick_fox.as_ref());

    let result = HasherContext::finish(&mut sha384hasher);
    assert_eq!(
        format!("{result:02x}"),
        "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
    );
}

#[test]
fn test() {
    let mut sha512hasher = Sha384Hasher::default();
    sha512hasher.write(b"your string here");

    let u64result = sha512hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512hasher);
    assert_eq!(u64result, 0x27C3D7DA682CF0AB);
    assert_eq!(
        format!("{bytes_result:02x}"),
        "27c3d7da682cf0ab27648e1f5da0a6c18ea13d9629e1ce7d9df1f38b1ee7dfb6ebf5aede6f8ddc9f8c2b9e96d29e4e63"
    );
    assert_eq!(
        format!("{bytes_result:02X}"),
        "27C3D7DA682CF0AB27648E1F5DA0A6C18EA13D9629E1CE7D9DF1F38B1EE7DFB6EBF5AEDE6F8DDC9F8C2B9E96D29E4E63"
    );
    assert_eq!(
        bytes_result,
        [
            0x27, 0xC3, 0xD7, 0xDA, 0x68, 0x2C, 0xF0, 0xAB, 0x27, 0x64, 0x8E, 0x1F, 0x5D, 0xA0, 0xA6, 0xC1, 0x8E, 0xA1,
            0x3D, 0x96, 0x29, 0xE1, 0xCE, 0x7D, 0x9D, 0xF1, 0xF3, 0x8B, 0x1E, 0xE7, 0xDF, 0xB6, 0xEB, 0xF5, 0xAE, 0xDE,
            0x6F, 0x8D, 0xDC, 0x9F, 0x8C, 0x2B, 0x9E, 0x96, 0xD2, 0x9E, 0x4E, 0x63
        ]
    )
}
