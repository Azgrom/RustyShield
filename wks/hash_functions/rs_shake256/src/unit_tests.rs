extern crate alloc;

use crate::{Shake256Hasher, Shake256State};
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let shake256state = Shake256State::<64>::default();
    let mut shake256hasher = shake256state.build_hasher();

    shake256hasher.write(b"");

    let output = HasherContext::finish(&mut shake256hasher);

    assert_eq!(format!("{output:02x}"), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
}

#[test]
fn testdsa() {
    let mut sha512_256hasher = Shake256Hasher::<20>::default();
    sha512_256hasher.write(b"your string here");

    let u64result = sha512_256hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512_256hasher);
    assert_eq!(u64result, 0x97E1C052B5574F11);
    assert_eq!(format!("{bytes_result:02x}"), "97e1c052b5574f117b3fb13f26865fb4eec4a473");
    assert_eq!(format!("{bytes_result:02X}"), "97E1C052B5574F117B3FB13F26865FB4EEC4A473");
    assert_eq!(
        bytes_result,
        [
            0x97, 0xE1, 0xC0, 0x52, 0xB5, 0x57, 0x4F, 0x11, 0x7B, 0x3F, 0xB1, 0x3F, 0x26, 0x86, 0x5F, 0xB4, 0xEE, 0xC4,
            0xA4, 0x73
        ]
    )
}
