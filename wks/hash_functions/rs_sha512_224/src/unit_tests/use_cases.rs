extern crate alloc;

use crate::Sha512_224Hasher;
use alloc::format;
use core::hash::Hasher;
use rs_hasher_ctx::HasherContext;

#[test]
fn test() {
    let mut sha512_224hasher = Sha512_224Hasher::default();
    sha512_224hasher.write(b"your string here");

    let u64result = sha512_224hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512_224hasher);
    assert_eq!(u64result, 0x233E7E4F520121E4);
    assert_eq!(format!("{bytes_result:02x}"), "233e7e4f520121e40eef63455e3b7f1815aabb985431e7afbbf880b3");
    assert_eq!(format!("{bytes_result:02X}"), "233E7E4F520121E40EEF63455E3B7F1815AABB985431E7AFBBF880B3");
    assert_eq!(
        bytes_result,
        [
            0x23, 0x3E, 0x7E, 0x4F, 0x52, 0x01, 0x21, 0xE4, 0x0E, 0xEF, 0x63, 0x45, 0x5E, 0x3B, 0x7F, 0x18, 0x15, 0xAA,
            0xBB, 0x98, 0x54, 0x31, 0xE7, 0xAF, 0xBB, 0xF8, 0x80, 0xB3
        ]
    )
}
