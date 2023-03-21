use crate::cavs_long_msg::CAVSLongMsg;
use rs_ssl::{HasherContext, Sha512_256State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha512_256_validation_system() {
    let cavs_tests = CAVSLongMsg::load("shabytetestvectors/SHA512_256LongMsg.rsp");
    let sha512_256state = Sha512_256State::default();

    for long_msg in cavs_tests.iter() {
        let mut sha512_256hasher = sha512_256state.build_hasher();

        sha512_256hasher.write(long_msg.message.as_ref());

        assert_eq!(
            format!("{:016x}", HasherContext::finish(&mut sha512_256hasher)),
            long_msg.message_digest
        );
    }
}
