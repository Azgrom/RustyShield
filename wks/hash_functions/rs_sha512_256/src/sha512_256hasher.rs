use crate::Sha512_256State;
use hash_ctx_lib::define_sha_hasher;

define_sha_hasher!(Sha512_256Hasher, Sha512_256State, u128);
