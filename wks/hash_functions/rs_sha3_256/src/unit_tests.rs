extern crate alloc;

use crate::{Sha3_256Hasher, Sha3_256State};
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let sha3_256state = Sha3_256State::default();
    let mut sha3_256hasher = sha3_256state.build_hasher();

    sha3_256hasher.write(b"");

    let output = HasherContext::finish(&mut sha3_256hasher);

    assert_eq!(format!("{output:02x}"), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

#[test]
fn test() {
    let mut sha3_256hasher = Sha3_256Hasher::default();
    sha3_256hasher.write(b"your string here");

    let u64result = sha3_256hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha3_256hasher);
    assert_eq!(u64result, 0x4722CA201B0E3369);
    assert_eq!(format!("{bytes_result:02x}"), "4722ca201b0e33697597ff6abd97e83b73c4ebd2f680b3ac23616e96dc351648");
    assert_eq!(format!("{bytes_result:02X}"), "4722CA201B0E33697597FF6ABD97E83B73C4EBD2F680B3AC23616E96DC351648");
    assert_eq!(
        bytes_result,
        [
            0x47, 0x22, 0xCA, 0x20, 0x1B, 0x0E, 0x33, 0x69, 0x75, 0x97, 0xFF, 0x6A, 0xBD, 0x97, 0xE8, 0x3B, 0x73, 0xC4,
            0xEB, 0xD2, 0xF6, 0x80, 0xB3, 0xAC, 0x23, 0x61, 0x6E, 0x96, 0xDC, 0x35, 0x16, 0x48
        ]
    )
}
