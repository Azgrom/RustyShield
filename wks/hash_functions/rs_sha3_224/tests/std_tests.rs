use rs_sha3_224::Sha3_224State;
use std::collections::hash_map::DefaultHasher;
use std::hash::{BuildHasher, Hash, Hasher};

#[test]
fn sha3_224_state_hash() {
    let sha3_224state = Sha3_224State::default();
    let sha3_224hasher = sha3_224state.build_hasher();
    let mut default_hasher = DefaultHasher::default();

    let initial_default_hasher_result = default_hasher.clone().finish();

    sha3_224hasher.hash(&mut default_hasher);
    let final_default_hasher_result = default_hasher.finish();

    assert_ne!(final_default_hasher_result, initial_default_hasher_result);
}
