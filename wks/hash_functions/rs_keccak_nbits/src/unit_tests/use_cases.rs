extern crate alloc;

use crate::{NBitKeccakHasher, NBitKeccakState};
use alloc::format;
use core::hash::{BuildHasher, Hash, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn u8_keccak_18rate_24bytes() {
    let quick_fox = b"The quick brown fox jumps over the lazy dog";

    const RATE: usize = 18;
    const BYTES_OUTPUT_LENGTH: usize = 24;
    let keccak: NBitKeccakState<u8, RATE, BYTES_OUTPUT_LENGTH> = NBitKeccakState::default();
    let mut hasher = keccak.build_hasher();

    hasher.write(quick_fox);

    let u64result = hasher.finish();
    let bytes_result = HasherContext::finish(&mut hasher);
    assert_eq!(u64result, 0x32EFB96DFBF80718);
    assert_eq!(format!("{bytes_result:02x}"), "32efb96dfbf807182d277c3d908062e41b2b01a93c029eed");
    assert_eq!(format!("{bytes_result:02X}"), "32EFB96DFBF807182D277C3D908062E41B2B01A93C029EED");
    assert_eq!(
        bytes_result,
        [
            0x32, 0xEF, 0xB9, 0x6D, 0xFB, 0xF8, 0x07, 0x18, 0x2D, 0x27, 0x7C, 0x3D, 0x90, 0x80, 0x62, 0xE4, 0x1B, 0x2B,
            0x01, 0xA9, 0x3C, 0x02, 0x9E, 0xED
        ]
    );
}

#[test]
fn u16_keccak_18rate_24bytes() {
    let quick_fox = b"The quick brown fox jumps over the lazy dog";

    const RATE: usize = 18;
    const BYTES_OUTPUT_LENGTH: usize = 24;
    let keccak: NBitKeccakState<u16, RATE, BYTES_OUTPUT_LENGTH> = NBitKeccakState::default();
    let mut hasher = keccak.build_hasher();

    hasher.write(quick_fox);

    let u64result = hasher.finish();
    let bytes_result = HasherContext::finish(&mut hasher);
    assert_eq!(u64result, 0xF967941A80194CD2);
    assert_eq!(format!("{bytes_result:02x}"), "f967941a80194cd217521fdac2607106897e5d8fa3bf19a6");
    assert_eq!(format!("{bytes_result:02X}"), "F967941A80194CD217521FDAC2607106897E5D8FA3BF19A6");
    assert_eq!(
        bytes_result,
        [
            0xF9, 0x67, 0x94, 0x1A, 0x80, 0x19, 0x4C, 0xD2, 0x17, 0x52, 0x1F, 0xDA, 0xC2, 0x60, 0x71, 0x06, 0x89, 0x7E,
            0x5D, 0x8F, 0xA3, 0xBF, 0x19, 0xA6
        ]
    );
}

#[test]
fn first_module_level_example() {
    let mut keccakhasher = NBitKeccakState::<u32, 10, 24>::default().build_hasher();
    keccakhasher.write(b"hello world");
    let result = keccakhasher.finish();
    assert_eq!(result, 0xE4B4C1F4C2BBD6E6);
}

#[test]
fn second_module_level_example() {
    let hello = "hello";
    let mut keccakhasher1: NBitKeccakHasher<u32, 18, 24> = NBitKeccakHasher::default();
    let mut keccakhasher2: NBitKeccakHasher<u32, 18, 24> = NBitKeccakHasher::default();
    let mut keccakhasher3: NBitKeccakHasher<u32, 18, 24> = NBitKeccakHasher::default();

    keccakhasher1.write(hello.as_bytes());
    hello.hash(&mut keccakhasher2);
    keccakhasher3.write(hello.as_bytes());
    keccakhasher3.write(&[0xFF]);

    let u64result1 = keccakhasher1.finish();
    let u64result2 = keccakhasher2.finish();
    let u64result3 = keccakhasher3.finish();

    assert_eq!(u64result1, 0x5A6B41FBBA8E0EFE);
    assert_eq!(u64result2, 0xA77CCB556D1FAE0A);
    assert_eq!(u64result2, u64result3);
    assert_ne!(u64result1, u64result2);
}
