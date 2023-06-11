use crate::cavs_long_msg::CAVSLongMsg;
use rs_shield::{HasherContext, Sha512State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha512_validation_system() {
    let cavs_tests = CAVSLongMsg::load("shabytetestvectors/SHA512LongMsg.rsp");
    let sha512state = Sha512State::default();

    for long_msg in cavs_tests.iter() {
        let mut sha512hasher = sha512state.build_hasher();

        sha512hasher.write(long_msg.message.as_ref());

        assert_eq!(format!("{:02x}", HasherContext::finish(&mut sha512hasher)), long_msg.expected_message_digest);
    }
}
