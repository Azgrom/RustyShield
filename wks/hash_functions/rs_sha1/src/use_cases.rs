use crate::{Sha1Hasher, Sha1State};
use core::hash::{BuildHasher, Hash, Hasher};
use hash_ctx_lib::HasherContext;

#[test]
fn sha1_empty_string_prefix_collision_resiliency() {
    let empty_str = "";
    let default_sha1_state = Sha1State::default();
    let mut first_sha1hasher = default_sha1_state.build_hasher();
    let mut second_sha1hasher = default_sha1_state.build_hasher();
    let mut third_sha1hasher = default_sha1_state.build_hasher();

    empty_str.hash(&mut first_sha1hasher);
    second_sha1hasher.write(empty_str.as_ref());
    third_sha1hasher.write([empty_str.as_bytes(), &[0xFF]].concat().as_ref());

    assert_ne!(first_sha1hasher.finish(), second_sha1hasher.finish());
    assert_eq!(first_sha1hasher.finish(), third_sha1hasher.finish());
    assert_eq!(
        first_sha1hasher.to_lower_hex(),
        "85e53271e14006f0265921d02d4d736cdc580b0b"
    );
    assert_eq!(
        second_sha1hasher.to_lower_hex(),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
}

#[test]
fn sha1_abc_string_prefix_collision_resiliency() {
    let abc = "abc";
    let mut abc_sha1_ctx = Sha1Hasher::default();
    abc_sha1_ctx.write(abc.as_ref());
    abc_sha1_ctx.finish();
    let digest_result = abc_sha1_ctx.to_lower_hex();
    assert_eq!(digest_result, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn sha1_abcd_string_prefix_collision_resiliency() {
    let abcd = "abcd";
    let mut abcd_sha1_ctx = Sha1Hasher::default();
    abcd_sha1_ctx.write(abcd.as_ref());
    abcd_sha1_ctx.finish();
    let digest_result = abcd_sha1_ctx.to_lower_hex();
    assert_eq!(digest_result, "81fe8bfe87576c3ecb22426f8e57847382917acf");
}

#[test]
fn sha1_quick_fox_string_prefix_collision_resiliency() {
    let quick_fox = "The quick brown fox jumps over the lazy dog";

    let mut quick_fox_sha1_ctx = Sha1Hasher::default();
    quick_fox_sha1_ctx.write(quick_fox.as_ref());
    quick_fox_sha1_ctx.finish();
    let digest_result = quick_fox_sha1_ctx.to_lower_hex();
    assert_eq!(digest_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
}

#[test]
fn sha1_lazy_cog_string_prefix_collision_resiliency() {
    let lazy_cog = "The quick brown fox jumps over the lazy cog";
    let mut lazy_cog_sha1_ctx = Sha1Hasher::default();
    lazy_cog_sha1_ctx.write(lazy_cog.as_ref());
    lazy_cog_sha1_ctx.finish();
    let digest_result = lazy_cog_sha1_ctx.to_lower_hex();
    assert_eq!(digest_result, "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
}

#[test]
fn sha1_abc_sequence_string_prefix_collision_resiliency() {
    let ab = "ab";
    let c = "c";
    let abc = "abc";
    let d = "d";
    let abcd = "abcd";

    let sha1_default_state = Sha1State::default();
    let mut ab_then_c_sha1hasher = sha1_default_state.build_hasher();
    let mut abc_sha1hasher = sha1_default_state.build_hasher();
    let mut ab_then_c_then_d_sha1hasher = sha1_default_state.build_hasher();
    let mut abcd_sha1hasher = sha1_default_state.build_hasher();

    ab.hash(&mut ab_then_c_sha1hasher);
    c.hash(&mut ab_then_c_sha1hasher);
    abc.hash(&mut abc_sha1hasher);
    ab.hash(&mut ab_then_c_then_d_sha1hasher);
    c.hash(&mut ab_then_c_then_d_sha1hasher);
    d.hash(&mut ab_then_c_then_d_sha1hasher);
    abcd.hash(&mut abcd_sha1hasher);

    assert_ne!(ab_then_c_sha1hasher.finish(), abc_sha1hasher.finish());
    assert_ne!(
        ab_then_c_then_d_sha1hasher.finish(),
        abcd_sha1hasher.finish()
    );
    assert_eq!(
        abc_sha1hasher.to_lower_hex(),
        "ba0ef8073ef81857932e1e4c81fbd3caade8e550"
    );
    assert_eq!(
        abcd_sha1hasher.to_lower_hex(),
        "519b619c2a42a52cbecffd23157c8d3b7c9a52b4"
    );
    assert_eq!(
        ab_then_c_sha1hasher.to_lower_hex(),
        "a7b178c8da94a38f49e55d54f2859b613b964edd"
    );
    assert_eq!(
        ab_then_c_then_d_sha1hasher.to_lower_hex(),
        "bb27718131043af8844d754cabbb3fc29b3f017c"
    );
}

#[test]
fn test_phrases_with_their_bytes_sequences() {
    let random_big_string = "";
    let mut big_str_sha1_ctx = Sha1Hasher::default();
    big_str_sha1_ctx.write(random_big_string.as_ref());
    let digest_result = big_str_sha1_ctx.to_bytes_hash();
    assert_eq!(
        digest_result.as_ref(),
        [
            0xdau8, 0x39u8, 0xa3u8, 0xeeu8, 0x5eu8, 0x6bu8, 0x4bu8, 0x0d, 0x32u8, 0x55u8, 0xbfu8,
            0xefu8, 0x95u8, 0x60u8, 0x18u8, 0x90u8, 0xafu8, 0xd8u8, 0x07u8, 0x09u8
        ]
    );
}
