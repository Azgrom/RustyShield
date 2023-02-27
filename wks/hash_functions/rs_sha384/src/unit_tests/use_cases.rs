use core::hash::{BuildHasher, Hash, Hasher};
use hash_ctx_lib::HasherContext;
use crate::sha384state::Sha384State;

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
        prefix_hasher.to_lower_hex(),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    )
}

#[test]
fn sha384_quick_fox_consistency() {
    let quick_fox = "The quick brown fox jumps over the lazy dog";
    let default_sha256state = Sha384State::default();
    let mut sha384hasher = default_sha256state.build_hasher();

    sha384hasher.write(quick_fox.as_ref());

    assert_eq!(sha384hasher.to_lower_hex(), "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1");
}
