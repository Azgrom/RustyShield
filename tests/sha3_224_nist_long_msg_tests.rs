use crate::cavs_long_msg::CAVSLongMsg;
use rs_ssl::{HasherContext, Sha3_224State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha3_224_validation_system() {
    let cavs_long_msg = CAVSLongMsg::load("shabytetestvectors/SHA3_224LongMsg.rsp");
    let sha3_224state = Sha3_224State::default();

    for long_msg in cavs_long_msg {
        let mut sha3_224hasher = sha3_224state.build_hasher();

        sha3_224hasher.write(long_msg.message.as_ref());

        let result = HasherContext::finish(&mut sha3_224hasher);
        assert_eq!(format!("{result:02x}"), long_msg.expected_message_digest);
    }
}
