extern crate alloc;

use crate::Sha512_256Hasher;
use alloc::format;
use core::hash::Hasher;
use rs_hasher_ctx::HasherContext;

#[test]
fn test() {
    let mut sha512_256hasher = Sha512_256Hasher::default();
    sha512_256hasher.write(b"your string here");

    let u64result = sha512_256hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512_256hasher);
    assert_eq!(u64result, 0xD6F2B480B2185883);
    assert_eq!(format!("{bytes_result:02x}"), "d6f2b480b21858837024cd2d4823c7baf48529d3688d407c7ef35a1f783c0b57");
    assert_eq!(format!("{bytes_result:02X}"), "D6F2B480B21858837024CD2D4823C7BAF48529D3688D407C7EF35A1F783C0B57");
    assert_eq!(
        bytes_result,
        [
            0xD6, 0xF2, 0xB4, 0x80, 0xB2, 0x18, 0x58, 0x83, 0x70, 0x24, 0xCD, 0x2D, 0x48, 0x23, 0xC7, 0xBA, 0xF4, 0x85,
            0x29, 0xD3, 0x68, 0x8D, 0x40, 0x7C, 0x7E, 0xF3, 0x5A, 0x1F, 0x78, 0x3C, 0x0B, 0x57
        ]
    )
}
