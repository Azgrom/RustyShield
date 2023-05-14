extern crate alloc;
use crate::Shake128Hasher;
use alloc::format;
use core::fmt::{Formatter, LowerHex};
use core::hash::Hasher;
use hash_ctx_lib::HasherContext;
use internal_state::LOWER_HEX_ERR;

const MSG: &[u8; 43] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn test() {
    let mut shake128hasher = Shake128Hasher::<32>::default();

    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);

    assert_eq!(shake128hasher.finish(), 0x250A744200F33112)
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

struct ByteArrayWrapper<const LEN: usize>([u8; LEN]);

impl<const LEN: usize> LowerHex for ByteArrayWrapper<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for b in self.0.iter().take(LEN - 1) {
            LowerHex::fmt(b, f).expect(LOWER_HEX_ERR);
        }

        LowerHex::fmt(&self.0[LEN - 1], f)
    }
}

#[test]
fn assert_abc_output() {
    let mut shake128hasher = Shake128Hasher::<10>::default();

    shake128hasher.write(b"abc");

    let context = HasherContext::finish(&mut shake128hasher);

    let wrapper = ByteArrayWrapper(context);
    assert_eq!(format!("{wrapper:02x}"), "5881092dd818bf5cf8a3");
}
