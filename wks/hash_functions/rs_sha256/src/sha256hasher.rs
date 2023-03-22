use crate::Sha256State;
use internal_hasher::define_sha_hasher;

define_sha_hasher!(Sha256Hasher, Sha256State, u64);

impl From<Sha256Hasher> for [u8; 32] {
    fn from(value: Sha256Hasher) -> Self {
        Into::<[u8; 32]>::into(value.state)
    }
}
