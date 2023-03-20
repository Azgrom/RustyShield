use crate::Sha1State;
use hash_ctx_lib::define_sha_hasher;

define_sha_hasher!(Sha1Hasher, Sha1State, u64);

impl From<Sha1Hasher> for [u8; 20] {
    fn from(value: Sha1Hasher) -> Self {
        Into::<[u8; 20]>::into(value.state)
    }
}
