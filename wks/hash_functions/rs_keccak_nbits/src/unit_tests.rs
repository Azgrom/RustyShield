extern crate alloc;

use crate::NBitKeccakState;
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use rs_hasher_ctx_lib::HasherContext;

#[test]
fn test() {
    let quick_fox = b"The quick brown fox jumps over the lazy dog";

    let keccak: NBitKeccakState<u8, 18, 24> = NBitKeccakState::default();
    let mut hasher = keccak.build_hasher();

    hasher.write(quick_fox);

    assert_eq!(hasher.finish(), 0x1807f8fb6db9ef32);
    let context = HasherContext::finish(&mut hasher);
    assert_eq!(format!("{context:02x}"), "32efb96dfbf807182d277c3d908062e41b2b01a93c029eed");
}
