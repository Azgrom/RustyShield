use internal_hasher::define_sha_hasher;
use crate::sha384state::Sha384State;

define_sha_hasher!(Sha384Hasher, Sha384State, u128);
