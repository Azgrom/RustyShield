extern crate alloc;
use crate::sha1state::{H0, H1, H2, H3, H4};
use crate::Sha1State;
use alloc::vec;
use core::hash::Hasher;
use rs_hasher_ctx::GenericHasher;
use rs_internal_hasher::{BigEndianBytes, BytePad};
use rs_internal_state::DWords;

const MESSAGE: &str = "abc";

fn instantiate_and_preprocess_abc_message() -> GenericHasher<Sha1State, 20> {
    let mut sha1hasher = GenericHasher::<Sha1State, 20>::default();
    Hasher::write(&mut sha1hasher, MESSAGE.as_ref());
    let pad_len: [u8; 8] = sha1hasher.padding.size.to_be_bytes();
    let zero_padding_length = 64 - ((sha1hasher.padding.size + pad_len.len()) % 64);
    let mut offset_pad = [0u8; 64];
    offset_pad[0] = 0x80;

    Hasher::write(&mut sha1hasher, &offset_pad[..zero_padding_length]);
    sha1hasher.padding[56..].clone_from_slice(&pad_len);

    sha1hasher
}

fn completed_words(hasher: &mut GenericHasher<Sha1State, 20>) {
    let pad_len: [u8; 8] = ((MESSAGE.len() as u64) * 8).to_be_bytes();
    let zero_padding_len = 64 - ((hasher.padding.size + pad_len.len()) % 64);
    let mut offset_pad = [0u8; 64];
    offset_pad[0] = 0x80;

    let mut len_w = hasher.padding.size & hasher.padding.last_index();
    let mut left = 64 - len_w;
    hasher.padding[len_w..len_w + left].clone_from_slice(&offset_pad[..left]);
    hasher.padding.size += zero_padding_len;

    len_w = hasher.padding.size % 64;
    left = 64 - len_w;
    hasher.padding[len_w..len_w + left].clone_from_slice(&pad_len);
    hasher.padding.size += zero_padding_len;
}

#[test]
fn start_processing_rounds_integrity() {
    let mut hasher = GenericHasher::<Sha1State, 20>::default();
    Hasher::write(&mut hasher, MESSAGE.as_ref());

    let expected_rounds_of_words_1: [u8; 64] =
        [vec![0x61, 0x62, 0x63, 0x00], vec![0u8; 60]].concat().try_into().unwrap();
    assert_eq!(hasher.padding, expected_rounds_of_words_1);

    completed_words(&mut hasher);

    let expected_rounds_of_words_2: [u8; 64] =
        [vec![0x61, 0x62, 0x63, 0x80], vec![0u8; 59], vec![0x18]].concat().try_into().unwrap();
    assert_eq!(hasher.padding, expected_rounds_of_words_2);
}

#[test]
fn assert_hash_values_integrity_for_each_step_00_to_15() {
    let mut hasher = instantiate_and_preprocess_abc_message();
    let words = DWords::<u32>::from(<&[u8; 64]>::try_from(hasher.padding.as_ref()).unwrap());
    completed_words(&mut hasher);

    let mut state = hasher.state.clone();

    assert_eq!([state.0, state.1, state.2, state.3, state.4], [H0, H1, H2, H3, H4]);

    Sha1State::t_00_19_round(&mut state, &words[0]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x0116FC33, 0x67452301, 0x7BF36AE2, 0x98BADCFE, 0x10325476]
    );

    Sha1State::t_00_19_round(&mut state, &words[1]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x8990536D, 0x0116FC33, 0x59D148C0, 0x7BF36AE2, 0x98BADCFE]
    );

    Sha1State::t_00_19_round(&mut state, &words[2]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xA1390F08, 0x8990536D, 0xC045BF0C, 0x59D148C0, 0x7BF36AE2]
    );

    Sha1State::t_00_19_round(&mut state, &words[3]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xCDD8E11B, 0xA1390F08, 0x626414DB, 0xC045BF0C, 0x59D148C0]
    );

    Sha1State::t_00_19_round(&mut state, &words[4]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xCFD499DE, 0xCDD8E11B, 0x284E43C2, 0x626414DB, 0xC045BF0C]
    );

    Sha1State::t_00_19_round(&mut state, &words[5]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x3FC7CA40, 0xCFD499DE, 0xF3763846, 0x284E43C2, 0x626414DB]
    );

    Sha1State::t_00_19_round(&mut state, &words[6]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x993E30C1, 0x3FC7CA40, 0xB3F52677, 0xF3763846, 0x284E43C2]
    );

    Sha1State::t_00_19_round(&mut state, &words[7]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x9E8C07D4, 0x993E30C1, 0x0FF1F290, 0xB3F52677, 0xF3763846]
    );

    Sha1State::t_00_19_round(&mut state, &words[8]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x4B6AE328, 0x9E8C07D4, 0x664F8C30, 0x0FF1F290, 0xB3F52677]
    );

    Sha1State::t_00_19_round(&mut state, &words[9]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x8351F929, 0x4B6AE328, 0x27A301F5, 0x664F8C30, 0xFF1F290]
    );

    Sha1State::t_00_19_round(&mut state, &words[10]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xFBDA9E89, 0x8351F929, 0x12DAB8CA, 0x27A301F5, 0x664F8C30]
    );

    Sha1State::t_00_19_round(&mut state, &words[11]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x63188FE4, 0xFBDA9E89, 0x60D47E4A, 0x12DAB8CA, 0x27A301F5]
    );

    Sha1State::t_00_19_round(&mut state, &words[12]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x4607B664, 0x63188FE4, 0x7EF6A7A2, 0x60D47E4A, 0x12DAB8CA]
    );

    Sha1State::t_00_19_round(&mut state, &words[13]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x9128F695, 0x4607B664, 0x18C623F9, 0x7EF6A7A2, 0x60D47E4A]
    );

    Sha1State::t_00_19_round(&mut state, &words[14]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x196BEE77, 0x9128F695, 0x1181ED99, 0x18C623F9, 0x7EF6A7A2]
    );

    Sha1State::t_00_19_round(&mut state, &words[15]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x20BDD62F, 0x196BEE77, 0x644A3DA5, 0x1181ED99, 0x18C623F9]
    );
}

#[test]
fn assert_hash_values_integrity_for_each_step_16_to_19() {
    let mut hasher = instantiate_and_preprocess_abc_message();
    let mut words = DWords::<u32>::from(<&[u8; 64]>::try_from(hasher.padding.as_ref()).unwrap());
    completed_words(&mut hasher);

    let mut state = hasher.state.clone();

    words.into_iter().fold(&mut state, Sha1State::t_00_19_round);
    Sha1State::next_words(&mut words);

    Sha1State::t_00_19_round(&mut state, &words[0]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x4E925823, 0x20BDD62F, 0xC65AFB9D, 0x644A3DA5, 0x1181ED99]
    );

    Sha1State::t_00_19_round(&mut state, &words[1]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x82AA6728, 0x4E925823, 0xC82F758B, 0xC65AFB9D, 0x644A3DA5]
    );

    Sha1State::t_00_19_round(&mut state, &words[2]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xDC64901D, 0x82AA6728, 0xD3A49608, 0xC82F758B, 0xC65AFB9D]
    );

    Sha1State::t_00_19_round(&mut state, &words[3]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xFD9E1D7D, 0xDC64901D, 0x20AA99CA, 0xD3A49608, 0xC82F758B]
    );

    Sha1State::t_20_39_round(&mut state, &words[4]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x1A37B0CA, 0xFD9E1D7D, 0x77192407, 0x20AA99CA, 0xD3A49608]
    );

    Sha1State::t_20_39_round(&mut state, &words[5]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x33A23BFC, 0x1A37B0CA, 0x7F67875F, 0x77192407, 0x20AA99CA]
    );

    Sha1State::t_20_39_round(&mut state, &words[6]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x21283486, 0x33A23BFC, 0x868DEC32, 0x7F67875F, 0x77192407]
    );

    Sha1State::t_20_39_round(&mut state, &words[7]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xD541F12D, 0x21283486, 0x0CE88EFF, 0x868DEC32, 0x7F67875F]
    );

    Sha1State::t_20_39_round(&mut state, &words[8]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xC7567DC6, 0xD541F12D, 0x884A0D21, 0x0CE88EFF, 0x868DEC32]
    );

    Sha1State::t_20_39_round(&mut state, &words[9]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x48413BA4, 0xC7567DC6, 0x75507C4B, 0x884A0D21, 0x0CE88EFF]
    );

    Sha1State::t_20_39_round(&mut state, &words[10]);
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xBE35FBD5, 0x48413BA4, 0xB1D59F71, 0x75507C4B, 0x884A0D21]
    );

    Sha1State::t_20_39_round(&mut state, &words[11]);
}
