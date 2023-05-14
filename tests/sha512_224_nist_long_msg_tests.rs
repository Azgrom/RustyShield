use crate::cavs_long_msg::CAVSLongMsg;
use rs_ssl::{HasherContext, Sha512_224State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha512_224_validation_system() {
    let cavs_tests = CAVSLongMsg::load("shabytetestvectors/SHA512_224LongMsg.rsp");
    let sha512_224state = Sha512_224State::default();

    for long_msg in cavs_tests.iter() {
        let mut sha512_224hasher = sha512_224state.build_hasher();

        sha512_224hasher.write(long_msg.message.as_ref());

        assert_eq!(format!("{:016x}", HasherContext::finish(&mut sha512_224hasher))[..56], long_msg.message_digest);
    }
}
