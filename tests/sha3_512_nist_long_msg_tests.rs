use crate::cavs_long_msg::CAVSLongMsg;
use rs_ssl::{HasherContext, Sha3_512State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_nist_sha3_512_validation_system() {
    let cavs_long_msg = CAVSLongMsg::load("shabytetestvectors/SHA3_512LongMsg.rsp");
    let sha3_512state = Sha3_512State::default();

    for long_msg in cavs_long_msg {
        let mut sha3_512hasher = sha3_512state.build_hasher();

        sha3_512hasher.write(long_msg.message.as_slice());

        let result = HasherContext::finish(&mut sha3_512hasher)
            .map(|b| format!("{b:02x}"))
            .iter()
            .flat_map(|s| s.chars())
            .collect::<String>();
        assert_eq!(result, long_msg.expected_message_digest);
    }
}
