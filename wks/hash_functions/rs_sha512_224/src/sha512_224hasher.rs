use crate::Sha512_224State;
use hash_ctx_lib::define_sha_hasher;
define_sha_hasher!(Sha512_224Hasher, Sha512_224State, u128);
