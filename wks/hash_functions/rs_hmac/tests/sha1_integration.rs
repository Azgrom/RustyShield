use hash_ctx_lib::NewHasherContext;
use rs_hmac::Hmac;
use rs_sha1::{Sha1Hasher, Sha1State};
use std::hash::Hasher;

fn hmac_sha1(key: &[u8], msg: &[u8]) -> String {
    let mut sha1hmac = Hmac::<Sha1State>::new(key);
    sha1hmac.write(msg);
    let resulting_state = NewHasherContext::finish(&mut sha1hmac);

    format!("{resulting_state:08x}")
}

#[test]
fn assert_sha1_hmac_correctness() {
    let expected_string_result = hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog");

    assert_eq!(expected_string_result, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
}
