use cavs_long_msg::CAVSLongMsg;
use rs_ssl::{HasherContext, Sha256State};
use std::hash::{BuildHasher, Hasher};

mod cavs_long_msg;

#[test]
fn compare_long_messages_provided_by_sha256_validation_system() {
    let cavs_tests = CAVSLongMsg::load("shabytetestvectors/SHA256LongMsg.rsp");
    let sha256state = Sha256State::default();

    for long_msg in cavs_tests.iter() {
        let mut sha256hasher = sha256state.build_hasher();

        sha256hasher.write(long_msg.message.as_ref());

        assert_eq!(
            format!("{:08x}", HasherContext::finish(&mut sha256hasher)),
            long_msg.message_digest
        );
    }
}
