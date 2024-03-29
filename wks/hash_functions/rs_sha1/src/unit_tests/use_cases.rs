extern crate alloc;
use crate::{Sha1Hasher, Sha1State};
use alloc::format;
use core::hash::{BuildHasher, Hash, Hasher};
use rs_hasher_ctx::HasherContext;

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
        format!("{:02x}", HasherContext::finish(&mut first_sha1hasher)),
        "85e53271e14006f0265921d02d4d736cdc580b0b"
    );
    assert_eq!(
        format!("{:02x}", HasherContext::finish(&mut second_sha1hasher)),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
}

#[test]
fn sha1_abc_string_prefix_collision_resiliency() {
    let abc = "abc";
    let abc_sha1_ctx = Sha1State::default();
    let mut sha1hasher = abc_sha1_ctx.build_hasher();
    sha1hasher.write(abc.as_ref());

    assert_eq!(format!("{:02x}", HasherContext::finish(&mut sha1hasher)), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn sha1_abcd_string_prefix_collision_resiliency() {
    let abcd = "abcd";
    let abcd_sha1_ctx = Sha1State::default();
    let mut sha1hasher = abcd_sha1_ctx.build_hasher();
    sha1hasher.write(abcd.as_ref());

    assert_eq!(format!("{:02x}", HasherContext::finish(&mut sha1hasher)), "81fe8bfe87576c3ecb22426f8e57847382917acf");
}

#[test]
fn sha1_quick_fox_string_prefix_collision_resiliency() {
    let quick_fox = "The quick brown fox jumps over the lazy dog";

    let quick_fox_sha1_ctx = Sha1State::default();
    let mut sha1hasher = quick_fox_sha1_ctx.build_hasher();
    sha1hasher.write(quick_fox.as_ref());

    assert_eq!(format!("{:02x}", HasherContext::finish(&mut sha1hasher)), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
}

#[test]
fn sha1_lazy_cog_string_prefix_collision_resiliency() {
    let lazy_cog = "The quick brown fox jumps over the lazy cog";
    let lazy_cog_sha1_ctx = Sha1State::default();
    let mut sha1hasher = lazy_cog_sha1_ctx.build_hasher();
    sha1hasher.write(lazy_cog.as_ref());

    assert_eq!(format!("{:02x}", HasherContext::finish(&mut sha1hasher)), "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
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
    assert_ne!(ab_then_c_then_d_sha1hasher.finish(), abcd_sha1hasher.finish());

    assert_eq!(
        format!("{:02x}", HasherContext::finish(&mut abc_sha1hasher)),
        "ba0ef8073ef81857932e1e4c81fbd3caade8e550"
    );
    assert_eq!(
        format!("{:02x}", HasherContext::finish(&mut abcd_sha1hasher)),
        "519b619c2a42a52cbecffd23157c8d3b7c9a52b4"
    );
    assert_eq!(
        format!("{:02x}", HasherContext::finish(&mut ab_then_c_sha1hasher)),
        "a7b178c8da94a38f49e55d54f2859b613b964edd"
    );
    assert_eq!(
        format!("{:02x}", HasherContext::finish(&mut ab_then_c_then_d_sha1hasher)),
        "bb27718131043af8844d754cabbb3fc29b3f017c"
    );
}

#[test]
fn test_phrases_with_their_bytes_sequences() {
    let random_big_string = "";
    let big_str_sha1_ctx = Sha1State::default();
    let mut sha1hasher = big_str_sha1_ctx.build_hasher();
    sha1hasher.write(random_big_string.as_ref());
    let sha1state = HasherContext::finish(&mut sha1hasher);
    let digest_result = Into::<[u8; 20]>::into(sha1state);
    assert_eq!(
        digest_result.as_ref(),
        [
            0xdau8, 0x39u8, 0xa3u8, 0xeeu8, 0x5eu8, 0x6bu8, 0x4bu8, 0x0d, 0x32u8, 0x55u8, 0xbfu8, 0xefu8, 0x95u8,
            0x60u8, 0x18u8, 0x90u8, 0xafu8, 0xd8u8, 0x07u8, 0x09u8
        ]
    );
}

#[test]
fn test() {
    let mut sha1hasher = Sha1Hasher::default();

    sha1hasher.write(b"your string here");

    let u64result = sha1hasher.finish();
    let bytes_result = HasherContext::finish(&mut sha1hasher);
    assert_eq!(u64result, 0x7D2C170805790AFA);
    assert_eq!(format!("{bytes_result:02x}"), "7d2c170805790afac408349a9c266a123d1961be");
    assert_eq!(format!("{bytes_result:02X}"), "7D2C170805790AFAC408349A9C266A123D1961BE");
    assert_eq!(
        bytes_result,
        [
            0x7D, 0x2C, 0x17, 0x08, 0x05, 0x79, 0x0A, 0xFA, 0xC4, 0x08, 0x34, 0x9A, 0x9C, 0x26, 0x6A, 0x12, 0x3D, 0x19,
            0x61, 0xBE
        ]
    )
}
