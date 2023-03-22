use internal_hasher::define_sha_hasher;
use crate::Sha1State;

define_sha_hasher!(Sha1Hasher, Sha1State, u64);

impl From<Sha1Hasher> for [u8; 20] {
    fn from(value: Sha1Hasher) -> Self {
        Into::<[u8; 20]>::into(value.state)
    }
}
