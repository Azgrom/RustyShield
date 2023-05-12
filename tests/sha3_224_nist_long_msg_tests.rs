use std::hash::{BuildHasher, Hasher};
use crate::cavs_long_msg::CAVSLongMsg;
use rs_ssl::{HasherContext, Sha3_224State};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha3_224_validation_system() {
    let cavs_long_msg = CAVSLongMsg::load("shabytetestvectors/SHA3_224LongMsg.rsp");
    let sha3_224state = Sha3_224State::default();

    for cavs_long_msg in cavs_long_msg {
        let mut sha3_224hasher = sha3_224state.build_hasher();

        sha3_224hasher.write(cavs_long_msg.message.as_ref());

        let result = HasherContext::finish(&mut sha3_224hasher).map(|b| format!("{:02x}", b)).iter().flat_map(|s| s.chars()).collect::<String>();
        assert_eq!(result, cavs_long_msg.message_digest);
    }
}
