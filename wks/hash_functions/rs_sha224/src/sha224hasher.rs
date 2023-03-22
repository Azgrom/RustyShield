use internal_hasher::define_sha_hasher;
use crate::Sha224State;

define_sha_hasher!(Sha224Hasher, Sha224State, u64);

impl From<Sha224Hasher> for [u8; 28] {
    fn from(value: Sha224Hasher) -> Self {
        Into::<[u8; 28]>::into(value.state)
    }
}
