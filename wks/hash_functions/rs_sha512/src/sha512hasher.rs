use crate::Sha512State;
use hash_ctx_lib::define_sha_hasher;

define_sha_hasher!(Sha512Hasher, Sha512State, u128);
