extern crate alloc;
use crate::Sha256State;
use alloc::format;
use core::hash::{BuildHasher, Hash, Hasher};
use hash_ctx_lib::HasherContext;

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
