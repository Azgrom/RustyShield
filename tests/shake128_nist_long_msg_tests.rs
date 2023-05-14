use std::hash::{BuildHasher, Hasher};
use hash_ctx_lib::HasherContext;
use rs_ssl::Shake128State;
use crate::cavs_long_msg::CAVSLongMsg;

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_nist_shake128_validation_system() {
    let cavs_long_msg = CAVSLongMsg::load("shabytetestvectors/SHAKE128LongMsg.rsp");
    let shake128state = Shake128State::<16>::default();

    for long_msg in cavs_long_msg {
        let mut shake128hasher = shake128state.build_hasher();

        shake128hasher.write(long_msg.message.as_ref());

        let result = HasherContext::finish(&mut shake128hasher)
            .map(|b| format!("{b:02x}"))
            .iter()
            .flat_map(|s| s.chars())
            .collect::<String>();

        assert_eq!(result, long_msg.expected_message_digest);
    }
}
