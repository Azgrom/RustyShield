extern crate alloc;
use crate::Shake128Hasher;
use alloc::format;
use core::hash::Hasher;
use rs_hasher_ctx::HasherContext;

const MSG: &[u8; 43] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn test() {
    let mut shake128hasher = Shake128Hasher::<32>::default();

    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);

    let u64result = shake128hasher.finish();
    assert_eq!(u64result, 0x1231F30042740A25)
}

#[test]
fn test2() {
    let mut shake128hasher = Shake128Hasher::<32>::default();

    shake128hasher.write(MSG);

    let context = HasherContext::finish(&mut shake128hasher);
    assert_eq!(
        context,
        [
            244, 32, 46, 60, 88, 82, 249, 24, 42, 4, 48, 253, 129, 68, 240, 167, 75, 149, 231, 65, 126, 202, 225, 125,
            176, 248, 207, 238, 208, 227, 230, 110
        ]
    );
}

#[test]
fn assert_abc_output() {
    let mut shake128hasher = Shake128Hasher::<10>::default();

    shake128hasher.write(b"abc");

    let output = HasherContext::finish(&mut shake128hasher);

    assert_eq!(format!("{output:02x}"), "5881092dd818bf5cf8a3");
}

#[test]
fn readme_example() {
    let mut sha512_256hasher = Shake128Hasher::<20>::default();
    sha512_256hasher.write(b"your string here");

    let u64result = sha512_256hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha512_256hasher);
    assert_eq!(u64result, 0x9105E04821D530DE);
    assert_eq!(format!("{bytes_result:02x}"), "9105e04821d530de80ff68fac42a0fe164c744dd");
    assert_eq!(format!("{bytes_result:02X}"), "9105E04821D530DE80FF68FAC42A0FE164C744DD");
    assert_eq!(
        bytes_result,
        [
            0x91, 0x05, 0xE0, 0x48, 0x21, 0xD5, 0x30, 0xDE, 0x80, 0xFF, 0x68, 0xFA, 0xC4, 0x2A, 0x0F, 0xE1, 0x64, 0xC7,
            0x44, 0xDD
        ]
    )
}
