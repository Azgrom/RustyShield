use cavs_long_msg::CAVSLongMsg;
use std::hash::{BuildHasher, Hasher};
use hash_ctx_lib::NewHasherContext;
use rs_sha1::Sha1State;

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha1_validation_system() {
    let cavs_tests = CAVSLongMsg::load("shabytetestvectors/SHA1LongMsg.rsp");
    let sha1state = Sha1State::default();

    for long_msg in cavs_tests.iter() {
        let mut sha1hasher = sha1state.build_hasher();

        sha1hasher.write(long_msg.message.as_ref());

        assert_eq!(format!("{:08x}", NewHasherContext::finish(&mut sha1hasher)), long_msg.message_digest);
    }
}
