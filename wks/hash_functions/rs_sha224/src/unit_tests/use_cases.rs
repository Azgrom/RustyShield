use crate::sha224state::Sha224State;
use alloc::format;
use core::hash::{BuildHasher, Hash, Hasher};
use hash_ctx_lib::HasherContext;

#[test]
fn sha224_empty_string_prefix_collision_resiliency() {
    let empty_str = "";
    let default_sha256state = Sha224State::default();
    let mut prefix_free_hasher = default_sha256state.build_hasher();
    let mut prefix_hasher = default_sha256state.build_hasher();

    empty_str.hash(&mut prefix_free_hasher);
    prefix_hasher.write(empty_str.as_ref());

    assert_ne!(prefix_free_hasher.finish(), prefix_hasher.finish());

    let result = HasherContext::finish(&mut prefix_hasher);
    assert_eq!(format!("{result:08x}"), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
}

#[test]
fn sha224_quick_fox_consistency() {
    let quick_fox = "The quick brown fox jumps over the lazy dog";
    let default_sha256state = Sha224State::default();
    let mut sha256hasher = default_sha256state.build_hasher();

    sha256hasher.write(quick_fox.as_ref());

    let result = HasherContext::finish(&mut sha256hasher);
    assert_eq!(format!("{result:08x}"), "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");
}

#[test]
fn sha224_appending_dot_quick_fox_consistency() {
    let quick_fox = "The quick brown fox jumps over the lazy dog.";
    let default_sha256state = Sha224State::default();
    let mut sha256hasher = default_sha256state.build_hasher();

    sha256hasher.write(quick_fox.as_ref());

    let result = HasherContext::finish(&mut sha256hasher);
    assert_eq!(format!("{result:08x}"), "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c");
}
