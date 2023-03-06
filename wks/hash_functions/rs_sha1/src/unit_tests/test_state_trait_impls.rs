use crate::sha1state::{H0, H1, H2, H3, H4};
use crate::{Sha1Hasher, Sha1State};
use alloc::{format, string::String};
use core::{
    any::{Any, TypeId},
    hash::{BuildHasher, Hash},
};
use n_bit_words_lib::U32Word;

#[test]
fn build_default_sha1_state_hasher() {
    let state = Sha1State::default();
    let hasher_default = BuildHasher::build_hasher(&state);

    assert_eq!(hasher_default.type_id(), TypeId::of::<Sha1Hasher>());

    let mut custom_hasher = BuildHasher::build_hasher(&state);
    String::new().hash(&mut custom_hasher);
    assert_eq!(custom_hasher.type_id(), TypeId::of::<Sha1Hasher>());
    assert_ne!(custom_hasher, hasher_default);
}

#[test]
fn default_sha1_state() {
    let default_state = Sha1State::default();
    let expected_result = Sha1State(
        U32Word::from(H0),
        U32Word::from(H1),
        U32Word::from(H2),
        U32Word::from(H3),
        U32Word::from(H4),
    );

    assert_eq!(default_state, expected_result);
    assert_eq!(default_state.type_id(), expected_result.type_id());
}

#[test]
fn index_sha1_state() {
    let default_sha1_state = Sha1State::default();

    assert_eq!(default_sha1_state.0, U32Word::from(H0));
    assert_eq!(default_sha1_state.1, U32Word::from(H1));
    assert_eq!(default_sha1_state.2, U32Word::from(H2));
    assert_eq!(default_sha1_state.3, U32Word::from(H3));
    assert_eq!(default_sha1_state.4, U32Word::from(H4));
}

#[test]
fn index_mut_sha1_state() {
    let mut default_sha1_state: Sha1State = Sha1State::default();

    assert_eq!(default_sha1_state.0, U32Word::from(H0));
    default_sha1_state.0 = U32Word::from(u32::MAX);
    assert_ne!(default_sha1_state.0, U32Word::from(H0));
}

#[test]
fn lower_hex_format() {
    let state = Sha1State::default();
    let expected_result = "67452301efcdab8998badcfe10325476c3d2e1f0";
    assert_eq!(format!("{:08x}", state), expected_result);
}

#[test]
fn upper_hex_format() {
    let state = Sha1State::default();
    let expected_result = "67452301EFCDAB8998BADCFE10325476C3D2E1F0";

    assert_eq!(format!("{:08X}", state), expected_result);
}