use crate::cavs_long_msg::CAVSLongMsg;
use rs_shield::{HasherContext, Shake256State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_nist_shake256_validation_system() {
    let cavs_long_msg = CAVSLongMsg::load("shabytetestvectors/SHAKE256LongMsg.rsp");
    let shake256state = Shake256State::<32>::default();

    for long_msg in cavs_long_msg {
        let mut shake256hasher = shake256state.build_hasher();

        shake256hasher.write(long_msg.message.as_ref());

        let result = HasherContext::finish(&mut shake256hasher);
        assert_eq!(format!("{result:02x}"), long_msg.expected_message_digest);
    }
}
