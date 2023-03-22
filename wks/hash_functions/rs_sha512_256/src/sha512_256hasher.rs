use internal_hasher::define_sha_hasher;
use crate::Sha512_256State;

define_sha_hasher!(Sha512_256Hasher, Sha512_256State, u128);
