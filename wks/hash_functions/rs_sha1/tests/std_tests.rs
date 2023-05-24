use rs_sha1::Sha1State;
use std::{
    collections::{hash_map::DefaultHasher, HashSet},
    hash::{BuildHasher, Hash, Hasher},
};

#[test]
fn sha1_state_hash() {
    let default_sha1_state = Sha1State::default();
    let sha1hasher = default_sha1_state.build_hasher();
    let mut default_hasher = DefaultHasher::default();
    let initial_default_hasher_result = default_hasher.clone().finish();

    sha1hasher.hash(&mut default_hasher);
    let final_default_hasher_result = default_hasher.finish();

    assert_ne!(final_default_hasher_result, initial_default_hasher_result);
}

#[test]
fn state_hash_set() {
    let sha1state = Sha1State::default();
    let mut sha1set = HashSet::with_hasher(sha1state);

    sha1set.insert("");
    sha1set.insert("2");

    assert_eq!(sha1set.get(""), Some(&""));
    assert_eq!(sha1set.get("str"), None);
    assert_eq!(sha1set.len(), 2);
    assert!(sha1set.insert("str"));
    assert_eq!(sha1set.len(), 3);
}
