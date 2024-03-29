use cavs_long_msg::CAVSLongMsg;
use rs_shield::{HasherContext, Sha224State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha224_validation_system() {
    let cavs_tests = CAVSLongMsg::load("shabytetestvectors/SHA224LongMsg.rsp");
    let sha224state = Sha224State::default();

    for long_msg in cavs_tests.iter() {
        let mut sha224hasher = sha224state.build_hasher();

        sha224hasher.write(long_msg.message.as_ref());

        assert_eq!(format!("{:02x}", HasherContext::finish(&mut sha224hasher)), long_msg.expected_message_digest);
    }
}
