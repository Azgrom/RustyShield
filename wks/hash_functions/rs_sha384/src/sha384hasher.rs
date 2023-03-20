use crate::sha384state::Sha384State;
use hash_ctx_lib::define_sha_hasher;

define_sha_hasher!(Sha384Hasher, Sha384State, u128);
