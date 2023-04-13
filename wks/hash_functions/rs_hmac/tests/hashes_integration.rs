use rs_hmac::Hmac;
use rs_sha1::Sha1State;
use rs_sha224::Sha224State;
use rs_sha256::Sha256State;
use rs_sha512::Sha512State;

const KEY: &[u8; 3] = b"key";
const MSG: &[u8; 43] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn assert_sha1_hmac_correctness() {
    let expected_string_result = format!("{:08x}", Hmac::<Sha1State>::digest(KEY, MSG));

    assert_eq!(expected_string_result, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
}

#[test]
fn assert_sha224_hmac_correctness() {
    let expected_string_result = format!("{:08x}", Hmac::<Sha224State>::digest(KEY, MSG));

    assert_eq!(expected_string_result, "88ff8b54675d39b8f72322e65ff945c52d96379988ada25639747e69");
}

#[test]
fn assert_sha256_hmac_correctness() {
    let expected_string_result = format!("{:08x}", Hmac::<Sha256State>::digest(KEY, MSG));

    assert_eq!(expected_string_result, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

#[test]
fn assert_sha512_hmac_correctness() {
    let expected_string_result = format!("{:016x}", Hmac::<Sha512State>::digest(KEY, MSG));

    assert_eq!(expected_string_result, "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a");
}
