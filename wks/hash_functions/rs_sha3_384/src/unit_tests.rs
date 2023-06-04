extern crate alloc;

use crate::{Sha3_384Hasher, Sha3_384State};
use alloc::format;
use core::hash::{BuildHasher, Hash, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let sha3_384state = Sha3_384State::default();
    let mut sha3_384hasher = sha3_384state.build_hasher();

    sha3_384hasher.write(b"");

    let output = HasherContext::finish(&mut sha3_384hasher);

    assert_eq!(
        format!("{output:02x}"),
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    );
}

#[test]
fn test() {
    let mut sha3_384hasher = Sha3_384Hasher::default();
    sha3_384hasher.write(b"your string here");

    let u64result = sha3_384hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha3_384hasher);
    assert_eq!(u64result, 0x75FD44A90B9A3689);
    assert_eq!(
        format!("{bytes_result:02x}"),
        "75fd44a90b9a3689f55dd3d09006bf31f8443752cc662a277914c32e772aa33431d306f4b174ccaf3abdb7eff384063d"
    );
    assert_eq!(
        format!("{bytes_result:02X}"),
        "75FD44A90B9A3689F55DD3D09006BF31F8443752CC662A277914C32E772AA33431D306F4B174CCAF3ABDB7EFF384063D"
    );
    assert_eq!(
        bytes_result,
        [
            0x75, 0xFD, 0x44, 0xA9, 0x0B, 0x9A, 0x36, 0x89, 0xF5, 0x5D, 0xD3, 0xD0, 0x90, 0x06, 0xBF, 0x31, 0xF8, 0x44,
            0x37, 0x52, 0xCC, 0x66, 0x2A, 0x27, 0x79, 0x14, 0xC3, 0x2E, 0x77, 0x2A, 0xA3, 0x34, 0x31, 0xD3, 0x06, 0xF4,
            0xB1, 0x74, 0xCC, 0xAF, 0x3A, 0xBD, 0xB7, 0xEF, 0xF3, 0x84, 0x06, 0x3D
        ]
    )
}
