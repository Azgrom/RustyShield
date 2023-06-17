use core::hash::{Hash, Hasher};
use criterion::{black_box, Bencher};
use rs_shield::{
    Hmac, NBitKeccakState, Sha1Hasher, Sha1State, Sha224Hasher, Sha224State, Sha256Hasher, Sha256State, Sha384Hasher,
    Sha384State, Sha3_224Hasher, Sha3_224State, Sha3_256Hasher, Sha3_256State, Sha3_384Hasher, Sha3_384State,
    Sha3_512Hasher, Sha3_512State, Sha512Hasher, Sha512State, Sha512_224Hasher, Sha512_224State, Sha512_256Hasher,
    Sha512_256State, Shake128Hasher, Shake128State, Shake256Hasher, Shake256State,
};

#[allow(dead_code)]
const KEY: &str = "My girl wove six dozen plaid jackets before she quit";
#[allow(dead_code)]
const MSG: &str = "The quick fox jumps over the lazy dog";

#[allow(dead_code)]
pub(crate) struct SimpleHashersComparison;

#[allow(dead_code)]
impl SimpleHashersComparison {
    pub(crate) fn sha1_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha1hasher = Sha1Hasher::default();
            black_box(MSG).hash(&mut sha1hasher);
            let _ = sha1hasher.finish();
        })
    }

    pub(crate) fn sha224_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha224hasher = Sha224Hasher::default();
            black_box(MSG).hash(&mut sha224hasher);
            let _ = sha224hasher.finish();
        })
    }

    pub(crate) fn sha256_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha256hasher = Sha256Hasher::default();
            black_box(MSG).hash(&mut sha256hasher);
            let _ = sha256hasher.finish();
        })
    }

    pub(crate) fn sha384_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha384hasher = Sha384Hasher::default();
            black_box(MSG).hash(&mut sha384hasher);
            let _ = sha384hasher.finish();
        })
    }

    pub(crate) fn sha512_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha512hasher = Sha512Hasher::default();
            black_box(MSG).hash(&mut sha512hasher);
            let _ = sha512hasher.finish();
        })
    }

    pub(crate) fn sha512_224_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha512_224hasher = Sha512_224Hasher::default();
            black_box(MSG).hash(&mut sha512_224hasher);
            let _ = sha512_224hasher.finish();
        })
    }

    pub(crate) fn sha512_256_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha512_256hasher = Sha512_256Hasher::default();
            black_box(MSG).hash(&mut sha512_256hasher);
            let _ = sha512_256hasher.finish();
        })
    }

    pub(crate) fn sha3_224_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha3_224hasher = Sha3_224Hasher::default();
            black_box(MSG).hash(&mut sha3_224hasher);
            let _ = sha3_224hasher.finish();
        })
    }

    pub(crate) fn sha3_256_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha3_256hasher = Sha3_256Hasher::default();
            black_box(MSG).hash(&mut sha3_256hasher);
            let _ = sha3_256hasher.finish();
        })
    }

    pub(crate) fn sha3_384_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha3_384hasher = Sha3_384Hasher::default();
            black_box(MSG).hash(&mut sha3_384hasher);
            let _ = sha3_384hasher.finish();
        })
    }

    pub(crate) fn sha3_512_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut sha3_512hasher = Sha3_512Hasher::default();
            black_box(MSG).hash(&mut sha3_512hasher);
            let _ = sha3_512hasher.finish();
        })
    }

    pub(crate) fn shake128_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut shake128hasher = Shake128Hasher::<20>::default();
            black_box(MSG).hash(&mut shake128hasher);
            let _ = shake128hasher.finish();
        })
    }

    pub(crate) fn shake256_iteration(b: &mut Bencher) {
        b.iter(|| {
            let mut shake256hasher = Shake256Hasher::<20>::default();
            black_box(MSG).hash(&mut shake256hasher);
            let _ = shake256hasher.finish();
        })
    }
}

#[allow(dead_code)]
pub(crate) struct HmacHashersComparison;

#[allow(dead_code)]
impl HmacHashersComparison {
    pub(crate) fn hmac_sha1_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha1State, 20>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha224_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha224State, 28>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha256_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha256State, 32>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha384_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha384State, 48>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha512_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha512State, 64>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha512_224_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha512_224State, 28>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha512_256_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha512_256State, 32>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha3_224_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha3_224State, 28>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha3_256_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha3_256State, 32>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha3_384_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha3_384State, 48>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_sha3_512_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Sha3_512State, 64>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_shake128_64bytes_output_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Shake128State<64>, 64>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_shake256_64bytes_output_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<Shake256State<64>, 64>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_200bits_keccak_8lanes_rate_64bytes_output_iteration(b: &mut Bencher) {
        b.iter(|| Hmac::<NBitKeccakState<u8, 20, 64>, 64>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes())))
    }

    pub(crate) fn hmac_400bits_keccak_8lanes_rate_64bytes_output_iteration(b: &mut Bencher) {
        b.iter(|| {
            Hmac::<NBitKeccakState<u16, 20, 64>, 64>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes()))
        })
    }

    pub(crate) fn hmac_800bits_keccak_8lanes_rate_64bytes_output_iteration(b: &mut Bencher) {
        b.iter(|| {
            Hmac::<NBitKeccakState<u32, 20, 64>, 64>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes()))
        })
    }

    pub(crate) fn hmac_1600bits_keccak_8lanes_rate_64bytes_output_iteration(b: &mut Bencher) {
        b.iter(|| {
            Hmac::<NBitKeccakState<u64, 20, 64>, 64>::digest(black_box(KEY.as_bytes()), black_box(MSG.as_bytes()))
        })
    }
}
