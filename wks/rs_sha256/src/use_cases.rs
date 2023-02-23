use core::hash::{BuildHasher, Hash, Hasher};
use hash_ctx_lib::HasherContext;
use crate::Sha256State;

#[test]
fn sha256_empty_string_prefix_collision_resiliency() {
    let empty_str = "";
    let default_sha256state = Sha256State::default();
    let mut prefix_free_hasher = default_sha256state.build_hasher();
    let mut prefix_hasher = default_sha256state.build_hasher();

    empty_str.hash(&mut prefix_free_hasher);
    prefix_hasher.write(empty_str.as_ref());

    assert_ne!(prefix_free_hasher.finish(), prefix_hasher.finish());
    assert_eq!(prefix_hasher.to_lower_hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
}
