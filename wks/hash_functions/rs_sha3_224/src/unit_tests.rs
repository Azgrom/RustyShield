extern crate alloc;

use crate::Sha3_224State;
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use hash_ctx_lib::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let sha3_224state = Sha3_224State::default();
    let mut sha3_224hasher = sha3_224state.build_hasher();

    sha3_224hasher.write(b"");

    let output = HasherContext::finish(&mut sha3_224hasher);

    assert_eq!(format!("{output:02x}"), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
}

#[test]
fn assert_quick_fox_hash_correctness() {
    let sha3_224state = Sha3_224State::default();
    let mut sha3_224hasher = sha3_224state.build_hasher();

    sha3_224hasher.write(b"The quick brown fox jumps over the lazy dog");

    let output = HasherContext::finish(&mut sha3_224hasher);
    assert_eq!(format!("{output:02x}"), "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795")
}
