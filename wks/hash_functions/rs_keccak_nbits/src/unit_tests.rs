extern crate alloc;

use crate::NBitKeccakState;
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn test() {
    let quick_fox = b"The quick brown fox jumps over the lazy dog";

    let keccak: NBitKeccakState<u8, 18, 24> = NBitKeccakState::default();
    let mut hasher = keccak.build_hasher();

    hasher.write(quick_fox);

    assert_eq!(hasher.finish(), 0x32efb96dfbf80718);
    let context = HasherContext::finish(&mut hasher);
    assert_eq!(format!("{context:02x}"), "32efb96dfbf807182d277c3d908062e41b2b01a93c029eed");
    assert_eq!(format!("{context:02X}"), "32EFB96DFBF807182D277C3D908062E41B2B01A93C029EED");
}
