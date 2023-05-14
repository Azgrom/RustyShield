use std::hash::{BuildHasher, Hasher};
use hash_ctx_lib::HasherContext;
use rs_ssl::Sha3_384State;
use crate::cavs_long_msg::CAVSLongMsg;

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_nist_sha3_384_validation_system() {
    let cavs_long_msg = CAVSLongMsg::load("shabytetestvectors/SHA3_384LongMsg.rsp");
    let sha3_384state = Sha3_384State::default();

    for long_msg in cavs_long_msg {
        let mut sha3_384hasher = sha3_384state.build_hasher();

        sha3_384hasher.write(long_msg.message.as_ref());

        let result = HasherContext::finish(&mut sha3_384hasher)
            .map(|b| format!("{b:02x}"))
            .iter().flat_map(|s| s.chars())
            .collect::<String>();
        assert_eq!(result, long_msg.expected_message_digest);
    }
}