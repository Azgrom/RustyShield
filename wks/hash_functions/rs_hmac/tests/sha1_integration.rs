use rs_hmac::Hmac;
use rs_sha1::Sha1State;

fn hmac_sha1(key: &[u8], msg: &[u8]) -> String {
    format!("{:08x}", Hmac::<Sha1State>::digest(key, msg))
}

#[test]
fn assert_sha1_hmac_correctness() {
    let expected_string_result = hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog");

    assert_eq!(expected_string_result, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
}
