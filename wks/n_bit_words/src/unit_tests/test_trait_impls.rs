use crate::{NBitWord, TSize};
use core::any::TypeId;

type U32Word = NBitWord<u32>;

#[test]
fn instantiate_u32_word_with_from_trait() {
    let u32_word_id = TypeId::of::<U32Word>();
    let u32_id = TypeId::of::<u32>();

    assert_eq!(u32_word_id, TypeId::of::<U32Word>());
    assert_ne!(u32_id, u32_word_id);
}

#[test]
fn add_operation_should_wrap_by_default() {
    let u32_max = U32Word::from(u32::MAX);
    let u32_one = U32Word::from(1u32);
    let expected_result = U32Word::from(0u32);

    assert_eq!(u32_max + u32_one, expected_result);
}

#[test]
fn add_operation_with_u32_should_wrap_by_default() {
    let u32_max = U32Word::from(u32::MAX);
    let u32_one = 1u32;
    let expected_result = U32Word::from(0u32);

    assert_eq!(u32_max + u32_one, expected_result);
}

#[test]
fn being_added_with_u32_should_wrap_by_default() {
    let u32_max = U32Word::from(u32::MAX);
    let u32_one = 1u32;
    let expected_result = U32Word::from(0u32);

    assert_eq!(u32_one + u32_max, expected_result);
}

#[test]
fn assert_ch_consistency() {
    let ch1 = U32Word::ch(1.into(), 2.into(), 3.into());
    assert_eq!(ch1, 2);

    let ch2 = U32Word::ch(1000.into(), 2001.into(), 3002.into());
    assert_eq!(ch2, 3026);
}

#[test]
fn assert_parity_consistency() {
    let parity1 = U32Word::parity(1.into(), 2.into(), 3.into());
    assert_eq!(parity1, 0);

    let parity2 = U32Word::parity(1000.into(), 2001.into(), 3002.into());
    assert_eq!(parity2, 3971);
}

#[test]
fn assert_maj_consistency() {
    let maj1 = U32Word::maj(1.into(), 2.into(), 3.into());
    assert_eq!(maj1, 3);

    let maj2 = U32Word::maj(1000.into(), 2001.into(), 3002.into());
    assert_eq!(maj2, 1016);
}
