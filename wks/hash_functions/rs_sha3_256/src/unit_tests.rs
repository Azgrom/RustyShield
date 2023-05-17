extern crate alloc;

use crate::Sha3_256State;
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use hash_ctx_lib::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let sha3_256state = Sha3_256State::default();
    let mut sha3_256hasher = sha3_256state.build_hasher();

    sha3_256hasher.write(b"");

    let output = HasherContext::finish(&mut sha3_256hasher);

    assert_eq!(format!("{output:02x}"), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}
