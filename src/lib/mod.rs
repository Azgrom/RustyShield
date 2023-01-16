//! # rs-sha1 - API Documentation
//!
//! rs-sha1 is a implementation of the first Secure Hash Algorithm designed to provide a compliant
//! standard library  SHA-1 API

use core::{hash::Hasher, mem::size_of};

const U32_BYTES: usize = size_of::<u32>();

const SHA1_WORD_COUNT: u32 = 16;
const SHA_CBLOCK: u32 = SHA1_WORD_COUNT * U32_BYTES as u32;
const SHA_OFFSET_PAD: u32 = SHA_CBLOCK + 8;
const SHA_CBLOCK_LAST_INDEX: u32 = SHA_CBLOCK - 1;

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

const T_0_19: u32 = 0x5A827999;
const T_20_39: u32 = 0x6ED9EBA1;
const T_40_59: u32 = 0x8F1BBCDC;
const T_60_79: u32 = 0xCA62C1D6;

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

#[inline(always)]
fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}

mod block;
pub mod sha1_hasher;
pub mod sha1_state;

pub trait HashContext: Hasher {
    fn to_hex_string(&self) -> String;
    fn to_bytes_hash(&self) -> [u8; 20];
}

#[cfg(test)]
mod use_cases {
    use crate::sha1_hasher::Sha1Hasher;
    use crate::sha1_state::Sha1State;
    use crate::HashContext;
    use core::hash::{BuildHasher, Hash, Hasher};

    #[test]
    fn empty_string_prefix_collision_resiliency() {
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
            first_sha1hasher.to_hex_string(),
            "85e53271e14006f0265921d02d4d736cdc580b0b"
        );
        assert_eq!(
            second_sha1hasher.to_hex_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        let abc = "abc";
        let mut abc_sha1_ctx = Sha1Hasher::default();
        abc_sha1_ctx.write(abc.as_ref());
        abc_sha1_ctx.finish();
        let digest_result = abc_sha1_ctx.to_hex_string();
        assert_eq!(digest_result, "a9993e364706816aba3e25717850c26c9cd0d89d");

        let abcd = "abcd";
        let mut abcd_sha1_ctx = Sha1Hasher::default();
        abcd_sha1_ctx.write(abcd.as_ref());
        abcd_sha1_ctx.finish();
        let digest_result = abcd_sha1_ctx.to_hex_string();
        assert_eq!(digest_result, "81fe8bfe87576c3ecb22426f8e57847382917acf");

        let quick_fox = "The quick brown fox jumps over the lazy dog";

        let mut quick_fox_sha1_ctx = Sha1Hasher::default();
        quick_fox_sha1_ctx.write(quick_fox.as_ref());
        quick_fox_sha1_ctx.finish();
        let digest_result = quick_fox_sha1_ctx.to_hex_string();
        assert_eq!(digest_result, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");

        let lazy_cog = "The quick brown fox jumps over the lazy cog";
        let mut lazy_cog_sha1_ctx = Sha1Hasher::default();
        lazy_cog_sha1_ctx.write(lazy_cog.as_ref());
        lazy_cog_sha1_ctx.finish();
        let digest_result = lazy_cog_sha1_ctx.to_hex_string();
        assert_eq!(digest_result, "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
    }

    #[test]
    fn abc_string_prefix_collision_resiliency() {
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
            abc_sha1hasher.to_hex_string(),
            "ba0ef8073ef81857932e1e4c81fbd3caade8e550"
        );
        assert_eq!(
            abcd_sha1hasher.to_hex_string(),
            "519b619c2a42a52cbecffd23157c8d3b7c9a52b4"
        );
        assert_eq!(
            ab_then_c_sha1hasher.to_hex_string(),
            "a7b178c8da94a38f49e55d54f2859b613b964edd"
        );
        assert_eq!(
            ab_then_c_then_d_sha1hasher.to_hex_string(),
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
            digest_result,
            [
                0xdau8, 0x39u8, 0xa3u8, 0xeeu8, 0x5eu8, 0x6bu8, 0x4bu8, 0x0d, 0x32u8, 0x55u8,
                0xbfu8, 0xefu8, 0x95u8, 0x60u8, 0x18u8, 0x90u8, 0xafu8, 0xd8u8, 0x07u8, 0x09u8
            ]
        );
    }
}

#[cfg(test)]
mod hypothesis_and_coverage_assurance;

#[cfg(test)]
mod fips_pub_180_1_coverage;
