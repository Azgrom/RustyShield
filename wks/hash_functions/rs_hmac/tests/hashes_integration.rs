use rs_hmac::Hmac;
use rs_keccak_nbits::NBitKeccakState;
use rs_sha1::Sha1State;
use rs_sha224::Sha224State;
use rs_sha256::Sha256State;
use rs_sha384::Sha384State;
use rs_sha3_224::Sha3_224State;
use rs_sha3_256::Sha3_256State;
use rs_sha3_384::Sha3_384State;
use rs_sha3_512::Sha3_512State;
use rs_sha512::Sha512State;
use rs_shake128::Shake128State;
use rs_shake256::Shake256State;

const KEY: &[u8; 3] = b"key";
const MSG: &[u8; 43] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn assert_sha1_hmac_correctness() {
    let expected_result = Hmac::<Sha1State, 20>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
}

#[test]
fn assert_sha224_hmac_correctness() {
    let expected_result = Hmac::<Sha224State, 28>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "88ff8b54675d39b8f72322e65ff945c52d96379988ada25639747e69");
}

#[test]
fn assert_sha256_hmac_correctness() {
    let expected_result = Hmac::<Sha256State, 32>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

#[test]
fn assert_sha384_hmac_correctness() {
    let expected_result = Hmac::<Sha384State, 48>::digest(KEY, MSG);

    assert_eq!(
        format!("{expected_result:02x}"),
        "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237"
    );
}

#[test]
fn assert_sha512_hmac_correctness() {
    let expected_result = Hmac::<Sha512State, 64>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a");
}

#[test]
fn assert_sha3_224_hmac_correctness() {
    let expected_result = Hmac::<Sha3_224State, 28>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "ff6fa8447ce10fb1efdccfe62caf8b640fe46c4fb1007912bf85100f");
}

#[test]
fn assert_sha3_256_hmac_correctness() {
    let expected_result = Hmac::<Sha3_256State, 32>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "8c6e0683409427f8931711b10ca92a506eb1fafa48fadd66d76126f47ac2c333");
}

#[test]
fn assert_sha3_384_hmac_correctness() {
    let expected_result = Hmac::<Sha3_384State, 48>::digest(KEY, MSG);

    assert_eq!(
        format!("{expected_result:02x}"),
        "aa739ad9fcdf9be4a04f06680ade7a1bd1e01a0af64accb04366234cf9f6934a0f8589772f857681fcde8acc256091a2"
    );
}

#[test]
fn assert_sha3_512_hmac_correctness() {
    let expected_result = Hmac::<Sha3_512State, 64>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "237a35049c40b3ef5ddd960b3dc893d8284953b9a4756611b1b61bffcf53edd979f93547db714b06ef0a692062c609b70208ab8d4a280ceee40ed8100f293063");
}

#[test]
fn assert_shake128_hmac_correctness() {
    const OUTPUT_SIZE: usize = 20;
    let expected_result = Hmac::<Shake128State<OUTPUT_SIZE>, OUTPUT_SIZE>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "2bf83e52c97cda778f26cec0e8424cfbaa073295");
}

#[test]
fn assert_shake256_hmac_correctness() {
    const OUTPUT_SIZE: usize = 20;
    let expected_result = Hmac::<Shake256State<OUTPUT_SIZE>, OUTPUT_SIZE>::digest(KEY, MSG);

    assert_eq!(format!("{expected_result:02x}"), "c3b51ff7b6922f9b67e6d55fb26332bc0fa65783");
}

#[test]
fn assert_keccak_8bits_hmac_correctness() {
    const OUTPUT_SIZE: usize = 20;
    const RATE: usize = OUTPUT_SIZE;

    let expected_result = Hmac::<NBitKeccakState<u8, RATE, OUTPUT_SIZE>, OUTPUT_SIZE>::digest(KEY, MSG);
    assert_eq!(format!("{expected_result:02x}"), "d93d8475f950f5e1966b717239ff2abe85d88e7c");

    let expected_result = Hmac::<NBitKeccakState<u8, { RATE / 2 }, OUTPUT_SIZE>, OUTPUT_SIZE>::digest(KEY, MSG);
    assert_eq!(format!("{expected_result:02x}"), "934e4f3ee25f48026685e058afdc3a36e96a6209");
}

#[test]
fn assert_keccak_16bits_hmac_correctness() {
    const OUTPUT_SIZE: usize = 20;
    const RATE: usize = OUTPUT_SIZE;

    let expected_result = Hmac::<NBitKeccakState<u16, RATE, OUTPUT_SIZE>, OUTPUT_SIZE>::digest(KEY, MSG);
    assert_eq!(format!("{expected_result:02x}"), "d36576785712cd25a5578535cffdfc16a2178574");

    let expected_result = Hmac::<NBitKeccakState<u16, { RATE / 2 }, OUTPUT_SIZE>, OUTPUT_SIZE>::digest(KEY, MSG);
    assert_eq!(format!("{expected_result:02x}"), "1e43f0b5777d97f67d2fbfee09147f527f7abc2f");
}

#[test]
fn assert_keccak_32bits_hmac_correctness() {
    const OUTPUT_SIZE: usize = 20;
    const RATE: usize = OUTPUT_SIZE;

    let expected_result = Hmac::<NBitKeccakState<u32, RATE, OUTPUT_SIZE>, OUTPUT_SIZE>::digest(KEY, MSG);
    assert_eq!(format!("{expected_result:02x}"), "bc44bfcab164871a4d6abf59cd287d62704f6799");

    let expected_result = Hmac::<NBitKeccakState<u32, { RATE / 2 }, OUTPUT_SIZE>, OUTPUT_SIZE>::digest(KEY, MSG);
    assert_eq!(format!("{expected_result:02x}"), "822144ef7f4c1f5c4ce13eec78cf70da26e171b3");
}
