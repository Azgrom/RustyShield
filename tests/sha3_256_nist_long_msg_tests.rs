use std::hash::{BuildHasher, Hasher};
use hash_ctx_lib::HasherContext;
use rs_ssl::Sha3_256State;
use crate::cavs_long_msg::CAVSLongMsg;

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_nist_sha3_256_validation_system() {
    let cavs_long_msgs = CAVSLongMsg::load("shabytetestvectors/SHA3_256LongMsg.rsp");
    let sha3_256state = Sha3_256State::default();

    for long_msg in cavs_long_msgs {
        let mut sha3_256hasher = sha3_256state.build_hasher();

        sha3_256hasher.write(long_msg.message.as_ref());

        let result = HasherContext::finish(&mut sha3_256hasher).
            map(|b| format!("{b:02x}"))
            .iter()
            .flat_map(|s| s.chars())
            .collect::<String>();
        assert_eq!(result, long_msg.message_digest);
    }
}
