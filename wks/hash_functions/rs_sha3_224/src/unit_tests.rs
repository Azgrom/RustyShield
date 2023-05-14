use crate::Sha3_224State;
use alloc::format;
use alloc::string::String;
use core::hash::{BuildHasher, Hasher};
use hash_ctx_lib::HasherContext;

const MSG: &[u8; 43] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn test() {
    let sha3_224state = Sha3_224State::default();
    let mut sha3_224hasher = sha3_224state.build_hasher();

    sha3_224hasher.write(MSG);

    let output = HasherContext::finish(&mut sha3_224hasher);
    // assert_eq!(output, [0u8; 28]);
    assert_eq!(
        output.map(|b| format!("{:02x}", b)).iter().flat_map(|s| s.chars()).collect::<String>(),
        "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795"
    )
}
