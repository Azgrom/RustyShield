use std::ops::Range;
use crate::sha1_ctx::sha1_ctx_constants::{H_0, H_1, H_2, H_3, H_4, SHA_PADDING};
use crate::sha1_ctx::SHA1States;
use crate::Sha1Context;

type Sha1Output = [u8; 20];
type Sha1Padding = [u8; 64];
type Sha1ConfusingMatrix = [u32; 16];

/// Function type for sha1_recompression_step_T (uint32_t ihvin[5], uint32_t ihvout[5], const uint32_t me2[80], const uint32_t state[5]).
/// Where 0 <= T < 80
///     me2 is an expanded message (the expansion of an original message block XOR'ed with a disturbance vector's message block difference.)
///     state is the internal state (a,b,c,d,e) before step T of the SHA-1 compression function while processing the original message block.
/// The function will return:
///     ihvin: The reconstructed input chaining value.
///     ihvout: The reconstructed output chaining value.
type RecompressionType = fn(&mut u32, &mut u32, &u32, &u32);

/// A callback function type that can be set to be called when a collision block has been found:
///     void collision_block_callback(uint64_t byteoffset, const uint32_t ihvin1[5], const uint32_t ihvin2[5], const uint32_t m1[80], const uint32_t m2[80])
pub type CollisionBlockCallback = fn(usize, &u32, &u32, &u32, &u32);

pub(crate) trait DC {
    fn init() -> Self;

    fn set_safe_hash(&mut self, safe_hash: bool);

    fn set_use_ubc(&mut self, ubc_check: bool);

    fn set_detect_collision(&mut self, detect_collision: bool);

    fn set_detect_reduced_round_collision(&mut self, reduced_round_coll: bool);

    fn set_callback(&mut self, callback: Option<CollisionBlockCallback>);

    fn dc_update(&mut self, buffer: [u8; 64], len: usize);

    fn dc_final(&mut self, output: &mut [u8; 20]) -> bool;
}
