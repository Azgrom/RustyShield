use cavs_long_msg::CAVSLongMsg;
use hash_ctx_lib::HasherContext;
use rs_sha1_lib::Sha1State;
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha1_validation_system() {
    let cavs_tests = CAVSLongMsg::load("shabytetestvectors/SHA1LongMsg.rsp");
    let sha1state = Sha1State::default();

    for long_msg in cavs_tests.iter() {
        let mut sha1hasher = sha1state.build_hasher();

        sha1hasher.write(long_msg.message.as_ref());

        assert_eq!(format!("{:08x}", HasherContext::finish(&mut sha1hasher)), long_msg.message_digest);
    }
}
