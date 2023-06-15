extern crate alloc;

use crate::{Sha3_512Hasher, Sha3_512State};
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let sha3_512state = Sha3_512State::default();
    let mut sha3_512hasher = sha3_512state.build_hasher();

    sha3_512hasher.write(b"");

    let output = HasherContext::finish(&mut sha3_512hasher);

    assert_eq!(format!("{output:02x}"), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}

#[test]
fn test() {
    let mut sha3_512hasher = Sha3_512Hasher::default();
    sha3_512hasher.write(b"your string here");

    let u64result = sha3_512hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha3_512hasher);
    assert_eq!(u64result, 0x8FB6BC7A78EA3DDD);
    assert_eq!(
    format!("{bytes_result:02x}"),
    "8fb6bc7a78ea3ddd267454718826f2b01b373dac4f947a2c7e0e0e27360392a58065e399062d837b53ed0413239d555fc5eac5b8a43c4c37684d1d6d30cb7fa3"
);
    assert_eq!(
    format!("{bytes_result:02X}"),
    "8FB6BC7A78EA3DDD267454718826F2B01B373DAC4F947A2C7E0E0E27360392A58065E399062D837B53ED0413239D555FC5EAC5B8A43C4C37684D1D6D30CB7FA3"
);
    assert_eq!(
        bytes_result,
        [
            0x8F, 0xB6, 0xBC, 0x7A, 0x78, 0xEA, 0x3D, 0xDD, 0x26, 0x74, 0x54, 0x71, 0x88, 0x26, 0xF2, 0xB0, 0x1B, 0x37,
            0x3D, 0xAC, 0x4F, 0x94, 0x7A, 0x2C, 0x7E, 0x0E, 0x0E, 0x27, 0x36, 0x03, 0x92, 0xA5, 0x80, 0x65, 0xE3, 0x99,
            0x06, 0x2D, 0x83, 0x7B, 0x53, 0xED, 0x04, 0x13, 0x23, 0x9D, 0x55, 0x5F, 0xC5, 0xEA, 0xC5, 0xB8, 0xA4, 0x3C,
            0x4C, 0x37, 0x68, 0x4D, 0x1D, 0x6D, 0x30, 0xCB, 0x7F, 0xA3
        ]
    )
}
