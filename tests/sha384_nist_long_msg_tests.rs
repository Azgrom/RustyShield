use crate::cavs_long_msg::CAVSLongMsg;
use rs_shield::{HasherContext, Sha384State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha384_validation_system() {
    let cavs_tests = CAVSLongMsg::load("shabytetestvectors/SHA384LongMsg.rsp");
    let sha384state = Sha384State::default();

    for long_msg in cavs_tests.iter() {
        let mut sha384hasher = sha384state.build_hasher();

        sha384hasher.write(long_msg.message.as_ref());

        assert_eq!(format!("{:02x}", HasherContext::finish(&mut sha384hasher)), long_msg.expected_message_digest);
    }
}
