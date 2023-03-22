use internal_hasher::define_sha_hasher;
use crate::Sha512State;

define_sha_hasher!(Sha512Hasher, Sha512State, u128);
