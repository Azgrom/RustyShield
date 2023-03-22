use internal_hasher::define_sha_hasher;
use crate::Sha512_224State;

define_sha_hasher!(Sha512_224Hasher, Sha512_224State, u128);
