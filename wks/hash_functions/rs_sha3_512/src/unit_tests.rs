extern crate alloc;

use crate::Sha3_512State;
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use rs_hasher_ctx_lib::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let sha3_512state = Sha3_512State::default();
    let mut sha3_512hasher = sha3_512state.build_hasher();

    sha3_512hasher.write(b"");

    let output = HasherContext::finish(&mut sha3_512hasher);

    assert_eq!(format!("{output:02x}"), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}
