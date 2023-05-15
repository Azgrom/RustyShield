extern crate alloc;

use crate::Sha3_384State;
use alloc::format;
use alloc::string::String;
use core::hash::{BuildHasher, Hasher};
use hash_ctx_lib::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let sha3_384state = Sha3_384State::default();
    let mut sha3_384hasher = sha3_384state.build_hasher();

    sha3_384hasher.write(b"");

    let output = HasherContext::finish(&mut sha3_384hasher);

    assert_eq!(
        convert_to_str(output),
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    );
}

fn convert_to_str(output: [u8; 48]) -> String {
    let string = output.map(|b| format!("{:02x}", b)).iter().flat_map(|s| s.chars()).collect::<String>();
    string
}
