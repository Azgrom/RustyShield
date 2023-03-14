use rs_sha1::Sha1State;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

#[test]
fn sha1_state_hash() {
    let default_sha1_state = Sha1State::default();
    let mut default_hasher = DefaultHasher::default();
    let initial_default_hasher_result = default_hasher.clone().finish();

    default_sha1_state.hash(&mut default_hasher);
    let final_default_hasher_result = default_hasher.finish();

    assert_ne!(final_default_hasher_result, initial_default_hasher_result);
}
