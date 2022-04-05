/***
* Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
* Distributed under the MIT Software License.
* See accompanying file LICENSE.txt or copy at
* https://opensource.org/licenses/MIT
***/

use disturbance_vectors_constants::{DV_MASK_SIZE, UBC_DV_EL};
use sha1_ctx_constants::{DO_STORE_STATE_00, DO_STORE_STATE_01, DO_STORE_STATE_02, DO_STORE_STATE_03, DO_STORE_STATE_04, DO_STORE_STATE_05, DO_STORE_STATE_06, DO_STORE_STATE_07, DO_STORE_STATE_08, DO_STORE_STATE_09, DO_STORE_STATE_10, DO_STORE_STATE_11, DO_STORE_STATE_12, DO_STORE_STATE_13, DO_STORE_STATE_14, DO_STORE_STATE_15, DO_STORE_STATE_16, DO_STORE_STATE_17, DO_STORE_STATE_18, DO_STORE_STATE_19, DO_STORE_STATE_20, DO_STORE_STATE_21, DO_STORE_STATE_22, DO_STORE_STATE_23, DO_STORE_STATE_24, DO_STORE_STATE_25, DO_STORE_STATE_26, DO_STORE_STATE_27, DO_STORE_STATE_28, DO_STORE_STATE_29, DO_STORE_STATE_30, DO_STORE_STATE_31, DO_STORE_STATE_32, DO_STORE_STATE_33, DO_STORE_STATE_34, DO_STORE_STATE_35, DO_STORE_STATE_36, DO_STORE_STATE_37, DO_STORE_STATE_38, DO_STORE_STATE_39, DO_STORE_STATE_40, DO_STORE_STATE_41, DO_STORE_STATE_42, DO_STORE_STATE_43, DO_STORE_STATE_44, DO_STORE_STATE_45, DO_STORE_STATE_46, DO_STORE_STATE_47, DO_STORE_STATE_48, DO_STORE_STATE_49, DO_STORE_STATE_50, DO_STORE_STATE_51, DO_STORE_STATE_52, DO_STORE_STATE_53, DO_STORE_STATE_54, DO_STORE_STATE_55, DO_STORE_STATE_56, DO_STORE_STATE_57, DO_STORE_STATE_58, DO_STORE_STATE_59, DO_STORE_STATE_60, DO_STORE_STATE_61, DO_STORE_STATE_62, DO_STORE_STATE_63, DO_STORE_STATE_64, DO_STORE_STATE_65, DO_STORE_STATE_66, DO_STORE_STATE_67, DO_STORE_STATE_68, DO_STORE_STATE_69, DO_STORE_STATE_70, DO_STORE_STATE_71, DO_STORE_STATE_72, DO_STORE_STATE_73, DO_STORE_STATE_74, DO_STORE_STATE_75, DO_STORE_STATE_76, DO_STORE_STATE_77, DO_STORE_STATE_78, DO_STORE_STATE_79, H_0, H_1, H_2, H_3, H_4, R1, R2, R3, R4, SHA1DC_BIG_ENDIAN};
use std::ops::{Add, BitAnd, BitOr, BitXor, Range};
use std::vec;
use types::{CollisionBlockCallback, DC};
use ubc_check::{DisturbanceVectorInfo, ubc_check};
use crate::sha1_ctx::sha1_ctx_constants::SHA_PADDING;

pub(crate) mod sha1_ctx_constants;
mod ubc_check;
pub(crate) mod disturbance_vectors_constants;
mod types;

#[derive(Copy, Clone)]
struct SHA1States {
    ihv1: [u32; 5],
    ihv2: [u32; 5],
    m1: [u32; 80],
    m2: [u32; 80],
    states: [[u32; 5]; 80],
}

impl SHA1States {
    fn new() -> Self {
        Self {
            ihv1: [0; 5],
            ihv2: [0; 5],
            m1: [0; 80],
            m2: [0; 80],
            states: [[0; 5]; 80],
        }
    }
}

pub struct Sha1Context {
    total: usize,
    ihv: [u32; 5],
    buffer: [u8; 64],
    found_collision: bool,
    detect_collision: bool,
    safe_hash: bool,
    ubc_check: bool,
    reduced_round_collision: bool,
    callback: Option<CollisionBlockCallback>,
    states: SHA1States,
}

// Library implementations
impl Sha1Context {
    fn choke_array<T>(x: &[T], y: &[T]) -> T
        where
            T: BitXor<Output = T> + BitOr<Output = T> + Copy + From<u32>,
    {
        x.iter()
            .zip(y.iter())
            .fold(<T>::try_from(0).unwrap(), |acc, (x_i, y_i)| {
                acc | *x_i ^ *y_i
            })
    }

    fn mix(d_words: &[u32; 80], i: &u8) -> u32 {
        let mut x = d_words[*i as usize - 3]
            ^ d_words[*i as usize - 8]
            ^ d_words[*i as usize - 14]
            ^ d_words[*i as usize - 16];
        return x.rotate_left(1);
    }
}

impl DC for Sha1Context {
    fn init() -> Self {
        Self {
            total: 0,
            ihv: [H_0, H_1, H_2, H_3, H_4],
            buffer: SHA_PADDING,
            found_collision: false,
            detect_collision: true,
            safe_hash: true,
            ubc_check: true,
            reduced_round_collision: false,
            callback: Some(CollisionBlockCallback),
            states: SHA1States::new(),
        }
    }

    /// Function to enable safe SHA-1 hashing:
    /// Collision attacks are thwarted by hashing a detected near-collision block 3 times.
    /// Think of it as extending SHA-1 from 80-steps to 240-steps for such blocks:
    ///     The best collision attacks against SHA-1 have complexity about 2^60,
    ///     thus for 240-steps an immediate lower-bound for the best cryptanalytic attacks would be 2^180.
    ///     An attacker would be better off using a generic birthday search of complexity 2^80.
    ///
    /// Enabling safe SHA-1 hashing will result in the correct SHA-1 hash for messages where no collision attack was detected,
    /// but it will result in a different SHA-1 hash for messages where a collision attack was detected.
    /// This will automatically invalidate SHA-1 based digital signature forgeries.
    /// Enabled by default.
    ///
    /// # Arguments
    ///
    /// * `safe_hash`:
    ///
    /// returns: ()
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    fn set_safe_hash(&mut self, safe_hash: bool) {
        if safe_hash {
            self.safe_hash = true;
        } else {
            self.safe_hash = false;
        }
    }

    /// Function to disable or enable the use of Unavoidable Bitconditions (provides a significant speed up).
    /// Enabled by default
    ///
    /// # Arguments
    ///
    /// * `ubc_check`:
    ///
    /// returns: ()
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    fn set_use_ubc(&mut self, ubc_check: bool) {
        if ubc_check {
            self.ubc_check = true;
        } else {
            self.ubc_check = false;
        }
    }

    /// Function to disable or enable the use of Collision Detection.
    /// Enabled by default.
    ///
    /// # Arguments
    ///
    /// * `detect_collision`:
    ///
    /// returns: ()
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    fn set_detect_collision(&mut self, detect_collision: bool) {
        if detect_collision {
            self.detect_collision = true;
        } else {
            self.detect_collision = false;
        }
    }

    /// Function to disable or enable the detection of reduced-round SHA-1 collisions
    /// Disabled by default
    ///
    /// # Arguments
    ///
    /// * `reduced_round_coll`:
    ///
    /// returns: ()
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    fn set_detect_reduced_round_collision(&mut self, reduced_round_coll: bool) {
        if reduced_round_coll {
            self.reduced_round_collision = true;
        } else {
            self.reduced_round_collision = false;
        }
    }

    /// Function to set a callback function, pass NULL to disable.
    /// By default no callback set
    ///
    /// # Arguments
    ///
    /// * `callback`:
    ///
    /// returns: ()
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    fn set_callback(&mut self, callback: Option<CollisionBlockCallback>) {
        self.callback = callback;
    }

    /// Update SHA-1 context with buffer contents
    ///
    /// # Arguments
    ///
    /// * `buffer`:
    /// * `len`:
    ///
    /// returns: ()
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    fn dc_update(&mut self, buffer: [u8; 80], mut len: usize) {
        if len == 0 {
            return;
        }

        let mut left = self.total & 63;
        let mut buffer_interval = Range {start: 0 , end: 64 };
        let fill = 64 - left;

        let mut buf = buffer.map(|x| x as u32);

        if (left & len) >= fill {
            self.total += fill;

            // self.buffer.copy_from_slice(&buffer[buffer_interval]);
            self.process(&mut buf);

            buffer_interval.start += fill;
            buffer_interval.end += fill;
            len -= fill as usize;
            left = 0;
        }

        while len >= 64 {
            self.total += 64;
            self.process(&mut buf);

            buffer_interval.start += 64;
            buffer_interval.end += 64;
            len -= 64;
        }

        if len > 0 {
            self.total += len;
            self.buffer = buf.map(|x| x as u8);
            // self.buffer[&range].copy_from_slice(&buffer[range]);
        }
    }

    /// Obtain SHA-1 hash from SHA-1 context
    ///
    /// # Arguments
    ///
    /// * `output`:
    ///
    /// returns: bool
    /// returns: 0 = no collision detected, otherwise = collision found => warn user for active attack
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    fn dc_final(&mut self, output: &mut [u8; 20]) -> bool {
        let last = self.total & 63;
        let mut padn;
        if last < 65 {
            padn = 56 - last;
        } else {
            padn = 120 - last;
        }
        let mut total = self.total.wrapping_sub(padn);
        total <<= 3;

        self.buffer[56] = (total >> 56) as u8;
        self.buffer[57] = (total >> 48) as u8;
        self.buffer[58] = (total >> 40) as u8;
        self.buffer[59] = (total >> 32) as u8;
        self.buffer[60] = (total >> 24) as u8;
        self.buffer[61] = (total >> 16) as u8;
        self.buffer[62] = (total >> 8) as u8;
        self.buffer[63] = total as u8;

        let mut buf = self.buffer.map(|x| x as u32);
        self.process(&mut buf);

        output[0] = (self.ihv[0] >> 24) as u8;
        output[1] = (self.ihv[0] >> 16) as u8;
        output[2] = (self.ihv[0] >> 8) as u8;
        output[3] = self.ihv[0] as u8;

        output[4] = (self.ihv[1] >> 24) as u8;
        output[5] = (self.ihv[1] >> 16) as u8;
        output[6] = (self.ihv[1] >> 8) as u8;
        output[7] = self.ihv[1] as u8;

        output[8] = (self.ihv[2] >> 24) as u8;
        output[9] = (self.ihv[2] >> 16) as u8;
        output[10] = (self.ihv[2] >> 8) as u8;
        output[11] = self.ihv[2] as u8;

        output[12] = (self.ihv[3] >> 24) as u8;
        output[13] = (self.ihv[3] >> 16) as u8;
        output[14] = (self.ihv[3] >> 8) as u8;
        output[15] = self.ihv[3] as u8;

        output[16] = (self.ihv[4] >> 24) as u8;
        output[17] = (self.ihv[4] >> 16) as u8;
        output[18] = (self.ihv[4] >> 8) as u8;
        output[19] = self.ihv[4] as u8;

        return self.found_collision;
    }
}

// Main business
impl Sha1Context {
    pub(crate) fn new() -> Self {
        Sha1Context::init()
    }



    fn load(t: u8, temp: &mut u32, m: &[u32; 80]) {
        *temp = m[t as usize];
        if SHA1DC_BIG_ENDIAN {
            *temp = temp.swap_bytes();
        }
    }

    fn store(w: &mut [u32; 80], i: u8, x: &u32) {
        w[i as usize] = *x;
    }

    fn process(&mut self, block: &mut [u32; 80]) {
        let mut ubc_dv_mask: [u32; DV_MASK_SIZE as usize] = [UBC_DV_EL];
        let mut ihv_tmp: [u32; 5] = [0; 5];

        self.states.ihv1.copy_from_slice(&self.ihv);

        self.compression_states(block);

        if self.detect_collision {
            self.detect_collision(&mut ubc_dv_mask, &mut ihv_tmp)
        }
    }

    fn detect_collision(
        &mut self,
        mut ubc_dv_mask: &mut [u32; DV_MASK_SIZE as usize],
        ihv_tmp: &mut [u32; 5],
    ) {
        if self.ubc_check {
            ubc_check(&self.states.m1, &mut ubc_dv_mask);
        }

        let sha1_dvs = disturbance_vectors_constants::SHA1_DISTURBANCE_VECTORS;

        if ubc_dv_mask[0] != 0 {
            let mut i: usize = 0;
            while sha1_dvs[i].dv_type != 0 {
                if (ubc_dv_mask[0] & (1u32 << sha1_dvs[i].mask_b)) != 0 {
                    for (index, dm) in sha1_dvs[i].dm.iter().enumerate() {
                        self.states.m2[index] = self.states.m1[index] ^ dm;
                    }

                    self.recompress_fast(i, ihv_tmp, &sha1_dvs);

                    if 0 == Sha1Context::choke_array(&self.ihv, ihv_tmp)
                        || (self.reduced_round_collision
                            && 0 == Sha1Context::choke_array(&self.states.ihv1, &self.states.ihv2))
                    {
                        self.found_collision = true;

                        if self.safe_hash {
                            self.compression_w();
                            self.compression_w();
                        }
                        break;
                    }
                }
                i += 1;
            }
        }
    }

    fn store_state(&mut self, i: u8, a: &u32, b: &u32, c: &u32, d: &u32, e: &u32) {
        self.states.states[i as usize][0] = *a;
        self.states.states[i as usize][1] = *b;
        self.states.states[i as usize][2] = *c;
        self.states.states[i as usize][3] = *d;
        self.states.states[i as usize][4] = *e;
    }
}

// Compression steps
impl Sha1Context {
    fn hash_clash_compress_round1_step(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        m: &[u32; 80],
    ) {
        *e += a.rotate_left(5) + Sha1Context::f1::<u32>(b, c, d) + R1 + m[t as usize];
        *b = b.rotate_left(30);
    }

    fn hash_clash_compress_round2_step(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        m: &[u32; 80],
    ) {
        *e += a.rotate_left(5) + Sha1Context::f2(b, c, d) + R2 + m[t as usize];
        *b = b.rotate_left(30);
    }

    fn hash_clash_compress_round3_step(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        m: &[u32; 80],
    ) {
        *e += a.rotate_left(5) + Sha1Context::f3(b, c, d) + R3 + m[t as usize];
        *b = b.rotate_left(30);
    }

    fn hash_clash_compress_round4_step(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        m: &[u32; 80],
    ) {
        *e += a.rotate_left(5) + Sha1Context::f2(b, c, d) + R4 + m[t as usize];
        *b = b.rotate_left(30);
    }

    fn hash_clash_compress_round1_step_bw(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        m: &[u32; 80],
    ) {
        *b = b.rotate_right(30);
        *e -= a.rotate_left(5) + Sha1Context::f1(b, c, d) + R1 + m[t as usize];
    }

    fn hash_clash_compress_round2_step_bw(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        m: &[u32; 80],
    ) {
        *b = b.rotate_right(30);
        *e -= a.rotate_left(5) + Sha1Context::f2(b, c, d) + R2 + m[t as usize];
    }

    fn hash_clash_compress_round3_step_bw(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        m: &[u32; 80],
    ) {
        *b = b.rotate_right(30);
        *e -= a.rotate_left(5) + Sha1Context::f3(b, c, d) + R3 + m[t as usize];
    }

    fn hash_clash_compress_round4_step_bw(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        m: &[u32; 80],
    ) {
        *b = b.rotate_right(30);
        *e -= a.rotate_left(5) + Sha1Context::f2(b, c, d) + R4 + m[t as usize];
    }

    fn compress_full_round1_step_load(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        temp: &mut u32,
        d_words: &mut [u32; 80],
        m: &mut [u32; 80],
    ) {
        Sha1Context::load(t, temp, m);
        Sha1Context::store(d_words, t, temp);
        *e = e.wrapping_add(temp.wrapping_add(a.rotate_left(5).wrapping_add(Sha1Context::f1(b, c, d).wrapping_add(R1))));
        *b = b.rotate_left(30);
    }

    fn compress_full_round1_step_expand(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        temp: &mut u32,
        d_words: &mut [u32; 80],
    ) {
        *temp = Sha1Context::mix(d_words, &t);
        Sha1Context::store(d_words, t, temp);
        *e = e.wrapping_add(temp.wrapping_add(a.rotate_left(5).wrapping_add(Sha1Context::f1(b, c, d).wrapping_add(R1))));
        *b = b.rotate_left(30);
    }

    fn compress_full_round2_step(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        temp: &mut u32,
        d_words: &mut [u32; 80],
    ) {
        *temp = Sha1Context::mix(d_words, &t);
        Sha1Context::store(d_words, t, temp);
        *e = e.wrapping_add(temp.wrapping_add(a.rotate_left(5).wrapping_add(Sha1Context::f2(b, c, d).wrapping_add(R2))));
        *b = b.rotate_left(30);
    }

    fn compress_full_round3_step(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        temp: &mut u32,
        d_words: &mut [u32; 80],
    ) {
        *temp = Sha1Context::mix(d_words, &t);
        Sha1Context::store(d_words, t, temp);
        *e = e.wrapping_add(temp.wrapping_add(a.rotate_left(5).wrapping_add(Sha1Context::f3(b, c, d).wrapping_add(R3))));
        *b = b.rotate_left(30);
    }

    fn compress_full_round4_step(
        a: &u32,
        b: &mut u32,
        c: &u32,
        d: &u32,
        e: &mut u32,
        t: u8,
        temp: &mut u32,
        d_words: &mut [u32; 80],
    ) {
        *temp = Sha1Context::mix(d_words, &t);
        Sha1Context::store(d_words, t, temp);
        *e = e.wrapping_add(temp.wrapping_add(a.rotate_left(5).wrapping_add(Sha1Context::f2(b, c, d).wrapping_add(R4))));
        *b = b.rotate_left(30);
    }
}

// Compression processes
impl Sha1Context {
    //TODO - Check later how to resume this process with iterators
    fn compression_states(&mut self, block: &mut [u32; 80]) {
        let mut a = self.ihv[0];
        let mut b = self.ihv[1];
        let mut c = self.ihv[2];
        let mut d = self.ihv[3];
        let mut e = self.ihv[4];
        let mut temp: u32 = 0;

        self.full_compress_load_round1_process(
            &mut a, &mut b, &mut c, &mut d, &mut e, &mut temp, block,
        );
        self.full_compress_expand_round1_process(
            &mut a, &mut b, &mut c, &mut d, &mut e, &mut temp, block,
        );
        self.full_compress_round2_process(&mut a, &mut b, &mut c, &mut d, &mut e, &mut temp, block);
        self.full_compress_round3_process(&mut a, &mut b, &mut c, &mut d, &mut e, &mut temp, block);
        self.full_compress_round4_process(&mut a, &mut b, &mut c, &mut d, &mut e, &mut temp, block);

        self.ihv[0] += a;
        self.ihv[1] += b;
        self.ihv[2] += c;
        self.ihv[3] += d;
        self.ihv[4] += e;

        // self.ihv[0] = self.ihv[0].wrapping_add(a);
        // self.ihv[1] = self.ihv[1].wrapping_add(b);
        // self.ihv[2] = self.ihv[2].wrapping_add(c);
        // self.ihv[3] = self.ihv[3].wrapping_add(d);
        // self.ihv[4] = self.ihv[4].wrapping_add(e);
    }

    fn full_compress_load_round1_process(
        &mut self,
        mut a: &mut u32,
        mut b: &mut u32,
        mut c: &mut u32,
        mut d: &mut u32,
        mut e: &mut u32,
        mut temp: &mut u32,
        d_word_block: &mut [u32; 80],
    ) {
        let round1_load_step = Sha1Context::compress_full_round1_step_load;

        if DO_STORE_STATE_00 {
            let state_number = 0;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &a,
            &mut b,
            &c,
            &d,
            &mut e,
            0,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_01 {
            let state_number = 1;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &e,
            &mut a,
            &b,
            &c,
            &mut d,
            1,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_02 {
            let state_number = 2;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &d,
            &mut e,
            &a,
            &b,
            &mut c,
            2,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_03 {
            let state_number = 3;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &c,
            &mut d,
            &e,
            &a,
            &mut b,
            3,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_04 {
            let state_number = 4;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &b,
            &mut c,
            &d,
            &e,
            &mut a,
            4,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_05 {
            let state_number = 5;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &a,
            &mut b,
            &c,
            &d,
            &mut e,
            5,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_06 {
            let state_number = 6;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &e,
            &mut a,
            &b,
            &c,
            &mut d,
            6,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_07 {
            let state_number = 7;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &d,
            &mut e,
            &a,
            &b,
            &mut c,
            7,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_08 {
            let state_number = 8;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &c,
            &mut d,
            &e,
            &a,
            &mut b,
            8,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_09 {
            let state_number = 9;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &b,
            &mut c,
            &d,
            &e,
            &mut a,
            9,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_10 {
            let state_number = 10;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &a,
            &mut b,
            &c,
            &d,
            &mut e,
            10,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_11 {
            let state_number = 11;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &e,
            &mut a,
            &b,
            &c,
            &mut d,
            11,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_12 {
            let state_number = 12;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &d,
            &mut e,
            &a,
            &b,
            &mut c,
            12,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_13 {
            let state_number = 13;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &c,
            &mut d,
            &e,
            &a,
            &mut b,
            13,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_14 {
            let state_number = 14;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &b,
            &mut c,
            &d,
            &e,
            &mut a,
            14,
            &mut temp,
            block,
            &mut self.states.m1,
        );

        if DO_STORE_STATE_15 {
            let state_number = 15;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_load_step(
            &a,
            &mut b,
            &c,
            &d,
            &mut e,
            15,
            &mut temp,
            block,
            &mut self.states.m1,
        );
    }

    fn full_compress_expand_round1_process(
        &mut self,
        mut a: &mut u32,
        mut b: &mut u32,
        mut c: &mut u32,
        mut d: &mut u32,
        mut e: &mut u32,
        mut temp: &mut u32,
        d_word_block: &mut [u32; 80],
    ) {
        let round1_expand_step = Sha1Context::compress_full_round1_step_expand;

        if DO_STORE_STATE_16 {
            let state_number = 16;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_expand_step(&e, &mut a, &b, &c, &mut d, 16, &mut temp, block);

        if DO_STORE_STATE_17 {
            let state_number = 17;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_expand_step(&d, &mut e, &a, &b, &mut c, 17, &mut temp, block);

        if DO_STORE_STATE_18 {
            let state_number = 18;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_expand_step(&c, &mut d, &e, &a, &mut b, 18, &mut temp, block);

        if DO_STORE_STATE_19 {
            let state_number = 19;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round1_expand_step(&b, &mut c, &d, &e, &mut a, 19, &mut temp, block);
    }

    fn full_compress_round2_process(
        &mut self,
        mut a: &mut u32,
        mut b: &mut u32,
        mut c: &mut u32,
        mut d: &mut u32,
        mut e: &mut u32,
        mut temp: &mut u32,
        d_word_block: &mut [u32; 80],
    ) {
        let round2_step = Sha1Context::compress_full_round2_step;

        if DO_STORE_STATE_20 {
            let state_number = 20;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&a, &mut b, &c, &d, &mut e, 20, &mut temp, block);

        if DO_STORE_STATE_21 {
            let state_number = 21;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&e, &mut a, &b, &c, &mut d, 21, &mut temp, block);

        if DO_STORE_STATE_22 {
            let state_number = 22;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&d, &mut e, &a, &b, &mut c, 22, &mut temp, block);

        if DO_STORE_STATE_23 {
            let state_number = 23;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&c, &mut d, &e, &a, &mut b, 23, &mut temp, block);

        if DO_STORE_STATE_24 {
            let state_number = 24;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&b, &mut c, &d, &e, &mut a, 24, &mut temp, block);

        if DO_STORE_STATE_25 {
            let state_number = 25;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&a, &mut b, &c, &d, &mut e, 25, &mut temp, block);

        if DO_STORE_STATE_26 {
            let state_number = 26;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&e, &mut a, &b, &c, &mut d, 26, &mut temp, block);

        if DO_STORE_STATE_27 {
            let state_number = 27;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&d, &mut e, &a, &b, &mut c, 27, &mut temp, block);

        if DO_STORE_STATE_28 {
            let state_number = 28;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&c, &mut d, &e, &a, &mut b, 28, &mut temp, block);

        if DO_STORE_STATE_29 {
            let state_number = 29;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&b, &mut c, &d, &e, &mut a, 29, &mut temp, block);

        if DO_STORE_STATE_30 {
            let state_number = 30;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&a, &mut b, &c, &d, &mut e, 30, &mut temp, block);

        if DO_STORE_STATE_31 {
            let state_number = 31;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&e, &mut a, &b, &c, &mut d, 31, &mut temp, block);

        if DO_STORE_STATE_32 {
            let state_number = 32;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&d, &mut e, &a, &b, &mut c, 32, &mut temp, block);

        if DO_STORE_STATE_33 {
            let state_number = 33;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&c, &mut d, &e, &a, &mut b, 33, &mut temp, block);

        if DO_STORE_STATE_34 {
            let state_number = 34;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&b, &mut c, &d, &e, &mut a, 34, &mut temp, block);

        if DO_STORE_STATE_35 {
            let state_number = 35;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&a, &mut b, &c, &d, &mut e, 35, &mut temp, block);

        if DO_STORE_STATE_36 {
            let state_number = 36;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&e, &mut a, &b, &c, &mut d, 36, &mut temp, block);

        if DO_STORE_STATE_37 {
            let state_number = 37;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&d, &mut e, &a, &b, &mut c, 37, &mut temp, block);

        if DO_STORE_STATE_38 {
            let state_number = 38;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&c, &mut d, &e, &a, &mut b, 38, &mut temp, block);

        if DO_STORE_STATE_39 {
            let state_number = 39;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round2_step(&b, &mut c, &d, &e, &mut a, 39, &mut temp, block);
    }

    fn full_compress_round3_process(
        &mut self,
        mut a: &mut u32,
        mut b: &mut u32,
        mut c: &mut u32,
        mut d: &mut u32,
        mut e: &mut u32,
        mut temp: &mut u32,
        d_word_block: &mut [u32; 80],
    ) {
        let round3_step = Sha1Context::compress_full_round3_step;

        if DO_STORE_STATE_40 {
            let state_number = 40;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&a, &mut b, &c, &d, &mut e, 40, &mut temp, block);

        if DO_STORE_STATE_41 {
            let state_number = 41;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&e, &mut a, &b, &c, &mut d, 41, &mut temp, block);

        if DO_STORE_STATE_42 {
            let state_number = 42;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&d, &mut e, &a, &b, &mut c, 42, &mut temp, block);

        if DO_STORE_STATE_43 {
            let state_number = 43;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&c, &mut d, &e, &a, &mut b, 43, &mut temp, block);

        if DO_STORE_STATE_44 {
            let state_number = 44;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&b, &mut c, &d, &e, &mut a, 44, &mut temp, block);

        if DO_STORE_STATE_45 {
            let state_number = 45;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&a, &mut b, &c, &d, &mut e, 45, &mut temp, block);

        if DO_STORE_STATE_46 {
            let state_number = 46;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&e, &mut a, &b, &c, &mut d, 46, &mut temp, block);

        if DO_STORE_STATE_47 {
            let state_number = 47;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&d, &mut e, &a, &b, &mut c, 47, &mut temp, block);

        if DO_STORE_STATE_48 {
            let state_number = 48;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&c, &mut d, &e, &a, &mut b, 48, &mut temp, block);

        if DO_STORE_STATE_49 {
            let state_number = 49;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&b, &mut c, &d, &e, &mut a, 49, &mut temp, block);

        if DO_STORE_STATE_50 {
            let state_number = 50;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&a, &mut b, &c, &d, &mut e, 50, &mut temp, block);

        if DO_STORE_STATE_51 {
            let state_number = 51;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&e, &mut a, &b, &c, &mut d, 51, &mut temp, block);

        if DO_STORE_STATE_52 {
            let state_number = 52;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&d, &mut e, &a, &b, &mut c, 52, &mut temp, block);

        if DO_STORE_STATE_53 {
            let state_number = 53;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&c, &mut d, &e, &a, &mut b, 53, &mut temp, block);

        if DO_STORE_STATE_54 {
            let state_number = 54;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&b, &mut c, &d, &e, &mut a, 54, &mut temp, block);

        if DO_STORE_STATE_55 {
            let state_number = 55;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&a, &mut b, &c, &d, &mut e, 55, &mut temp, block);

        if DO_STORE_STATE_56 {
            let state_number = 56;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&e, &mut a, &b, &c, &mut d, 56, &mut temp, block);

        if DO_STORE_STATE_57 {
            let state_number = 57;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&d, &mut e, &a, &b, &mut c, 57, &mut temp, block);

        if DO_STORE_STATE_58 {
            let state_number = 58;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&c, &mut d, &e, &a, &mut b, 58, &mut temp, block);

        if DO_STORE_STATE_59 {
            let state_number = 59;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round3_step(&b, &mut c, &d, &e, &mut a, 59, &mut temp, block);
    }

    fn full_compress_round4_process(
        &mut self,
        mut a: &mut u32,
        mut b: &mut u32,
        mut c: &mut u32,
        mut d: &mut u32,
        mut e: &mut u32,
        mut temp: &mut u32,
        d_word_block: &mut [u32; 80],
    ) {
        let round4_step = Sha1Context::compress_full_round4_step;

        if DO_STORE_STATE_60 {
            let state_number = 60;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&a, &mut b, &c, &d, &mut e, 60, &mut temp, block);

        if DO_STORE_STATE_61 {
            let state_number = 61;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&e, &mut a, &b, &c, &mut d, 61, &mut temp, block);

        if DO_STORE_STATE_62 {
            let state_number = 62;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&d, &mut e, &a, &b, &mut c, 62, &mut temp, block);

        if DO_STORE_STATE_63 {
            let state_number = 63;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&c, &mut d, &e, &a, &mut b, 63, &mut temp, block);

        if DO_STORE_STATE_64 {
            let state_number = 64;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&b, &mut c, &d, &e, &mut a, 64, &mut temp, block);

        if DO_STORE_STATE_65 {
            let state_number = 65;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&a, &mut b, &c, &d, &mut e, 65, &mut temp, block);

        if DO_STORE_STATE_66 {
            let state_number = 66;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&e, &mut a, &b, &c, &mut d, 66, &mut temp, block);

        if DO_STORE_STATE_67 {
            let state_number = 67;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&d, &mut e, &a, &b, &mut c, 67, &mut temp, block);

        if DO_STORE_STATE_68 {
            let state_number = 68;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&c, &mut d, &e, &a, &mut b, 68, &mut temp, block);

        if DO_STORE_STATE_69 {
            let state_number = 69;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&b, &mut c, &d, &e, &mut a, 69, &mut temp, block);

        if DO_STORE_STATE_70 {
            let state_number = 70;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&a, &mut b, &c, &d, &mut e, 70, &mut temp, block);

        if DO_STORE_STATE_71 {
            let state_number = 71;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&e, &mut a, &b, &c, &mut d, 71, &mut temp, block);

        if DO_STORE_STATE_72 {
            let state_number = 72;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&d, &mut e, &a, &b, &mut c, 72, &mut temp, block);

        if DO_STORE_STATE_73 {
            let state_number = 73;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&c, &mut d, &e, &a, &mut b, 73, &mut temp, block);

        if DO_STORE_STATE_74 {
            let state_number = 74;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&b, &mut c, &d, &e, &mut a, 74, &mut temp, block);

        if DO_STORE_STATE_75 {
            let state_number = 75;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&a, &mut b, &c, &d, &mut e, 75, &mut temp, block);

        if DO_STORE_STATE_76 {
            let state_number = 76;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&e, &mut a, &b, &c, &mut d, 76, &mut temp, block);

        if DO_STORE_STATE_77 {
            let state_number = 77;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&d, &mut e, &a, &b, &mut c, 77, &mut temp, block);

        if DO_STORE_STATE_78 {
            let state_number = 78;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&c, &mut d, &e, &a, &mut b, 78, &mut temp, block);

        if DO_STORE_STATE_79 {
            let state_number = 79;
            self.store_state(state_number, &a, &b, &c, &d, &e);
        }
        round4_step(&b, &mut c, &d, &e, &mut a, 79, &mut temp, block);
    }

    //TODO - Check later how to resume this process with iterators
    fn compression_w(&mut self) {
        let mut a = self.ihv[0];
        let mut b = self.ihv[1];
        let mut c = self.ihv[2];
        let mut d = self.ihv[3];
        let mut e = self.ihv[4];

        let hash_clash_round1 = Sha1Context::hash_clash_compress_round1_step;
        hash_clash_round1(&a, &mut b, &c, &d, &mut e, 0u8, &mut self.states.m1);
        hash_clash_round1(&e, &mut a, &b, &c, &mut d, 1u8, &mut self.states.m1);
        hash_clash_round1(&d, &mut e, &a, &b, &mut c, 2u8, &mut self.states.m1);
        hash_clash_round1(&c, &mut d, &e, &a, &mut b, 3u8, &mut self.states.m1);
        hash_clash_round1(&b, &mut c, &d, &e, &mut a, 4u8, &mut self.states.m1);
        hash_clash_round1(&a, &mut b, &c, &d, &mut e, 5u8, &mut self.states.m1);
        hash_clash_round1(&e, &mut a, &b, &c, &mut d, 6u8, &mut self.states.m1);
        hash_clash_round1(&d, &mut e, &a, &b, &mut c, 7u8, &mut self.states.m1);
        hash_clash_round1(&c, &mut d, &e, &a, &mut b, 8u8, &mut self.states.m1);
        hash_clash_round1(&b, &mut c, &d, &e, &mut a, 9u8, &mut self.states.m1);
        hash_clash_round1(&a, &mut b, &c, &d, &mut e, 10u8, &mut self.states.m1);
        hash_clash_round1(&e, &mut a, &b, &c, &mut d, 11u8, &mut self.states.m1);
        hash_clash_round1(&d, &mut e, &a, &b, &mut c, 12u8, &mut self.states.m1);
        hash_clash_round1(&c, &mut d, &e, &a, &mut b, 13u8, &mut self.states.m1);
        hash_clash_round1(&b, &mut c, &d, &e, &mut a, 14u8, &mut self.states.m1);
        hash_clash_round1(&a, &mut b, &c, &d, &mut e, 15u8, &mut self.states.m1);
        hash_clash_round1(&e, &mut a, &b, &c, &mut d, 16u8, &mut self.states.m1);
        hash_clash_round1(&d, &mut e, &a, &b, &mut c, 17u8, &mut self.states.m1);
        hash_clash_round1(&c, &mut d, &e, &a, &mut b, 18u8, &mut self.states.m1);
        hash_clash_round1(&b, &mut c, &d, &e, &mut a, 19u8, &mut self.states.m1);

        let hash_clash_round2 = Sha1Context::hash_clash_compress_round2_step;
        hash_clash_round2(&a, &mut b, &c, &d, &mut e, 20u8, &mut self.states.m1);
        hash_clash_round2(&e, &mut a, &b, &c, &mut d, 21u8, &mut self.states.m1);
        hash_clash_round2(&d, &mut e, &a, &b, &mut c, 22u8, &mut self.states.m1);
        hash_clash_round2(&c, &mut d, &e, &a, &mut b, 23u8, &mut self.states.m1);
        hash_clash_round2(&b, &mut c, &d, &e, &mut a, 24u8, &mut self.states.m1);
        hash_clash_round2(&a, &mut b, &c, &d, &mut e, 25u8, &mut self.states.m1);
        hash_clash_round2(&e, &mut a, &b, &c, &mut d, 26u8, &mut self.states.m1);
        hash_clash_round2(&d, &mut e, &a, &b, &mut c, 27u8, &mut self.states.m1);
        hash_clash_round2(&c, &mut d, &e, &a, &mut b, 28u8, &mut self.states.m1);
        hash_clash_round2(&b, &mut c, &d, &e, &mut a, 29u8, &mut self.states.m1);
        hash_clash_round2(&a, &mut b, &c, &d, &mut e, 30u8, &mut self.states.m1);
        hash_clash_round2(&e, &mut a, &b, &c, &mut d, 31u8, &mut self.states.m1);
        hash_clash_round2(&d, &mut e, &a, &b, &mut c, 32u8, &mut self.states.m1);
        hash_clash_round2(&c, &mut d, &e, &a, &mut b, 33u8, &mut self.states.m1);
        hash_clash_round2(&b, &mut c, &d, &e, &mut a, 34u8, &mut self.states.m1);
        hash_clash_round2(&a, &mut b, &c, &d, &mut e, 35u8, &mut self.states.m1);
        hash_clash_round2(&e, &mut a, &b, &c, &mut d, 36u8, &mut self.states.m1);
        hash_clash_round2(&d, &mut e, &a, &b, &mut c, 37u8, &mut self.states.m1);
        hash_clash_round2(&c, &mut d, &e, &a, &mut b, 38u8, &mut self.states.m1);
        hash_clash_round2(&b, &mut c, &d, &e, &mut a, 39u8, &mut self.states.m1);

        let hash_clash_round3 = Sha1Context::hash_clash_compress_round3_step;
        hash_clash_round3(&a, &mut b, &c, &d, &mut e, 40u8, &mut self.states.m1);
        hash_clash_round3(&e, &mut a, &b, &c, &mut d, 41u8, &mut self.states.m1);
        hash_clash_round3(&d, &mut e, &a, &b, &mut c, 42u8, &mut self.states.m1);
        hash_clash_round3(&c, &mut d, &e, &a, &mut b, 43u8, &mut self.states.m1);
        hash_clash_round3(&b, &mut c, &d, &e, &mut a, 44u8, &mut self.states.m1);
        hash_clash_round3(&a, &mut b, &c, &d, &mut e, 45u8, &mut self.states.m1);
        hash_clash_round3(&e, &mut a, &b, &c, &mut d, 46u8, &mut self.states.m1);
        hash_clash_round3(&d, &mut e, &a, &b, &mut c, 47u8, &mut self.states.m1);
        hash_clash_round3(&c, &mut d, &e, &a, &mut b, 48u8, &mut self.states.m1);
        hash_clash_round3(&b, &mut c, &d, &e, &mut a, 49u8, &mut self.states.m1);
        hash_clash_round3(&a, &mut b, &c, &d, &mut e, 50u8, &mut self.states.m1);
        hash_clash_round3(&e, &mut a, &b, &c, &mut d, 51u8, &mut self.states.m1);
        hash_clash_round3(&d, &mut e, &a, &b, &mut c, 52u8, &mut self.states.m1);
        hash_clash_round3(&c, &mut d, &e, &a, &mut b, 53u8, &mut self.states.m1);
        hash_clash_round3(&b, &mut c, &d, &e, &mut a, 54u8, &mut self.states.m1);
        hash_clash_round3(&a, &mut b, &c, &d, &mut e, 55u8, &mut self.states.m1);
        hash_clash_round3(&e, &mut a, &b, &c, &mut d, 56u8, &mut self.states.m1);
        hash_clash_round3(&d, &mut e, &a, &b, &mut c, 57u8, &mut self.states.m1);
        hash_clash_round3(&c, &mut d, &e, &a, &mut b, 58u8, &mut self.states.m1);
        hash_clash_round3(&b, &mut c, &d, &e, &mut a, 59u8, &mut self.states.m1);

        let hash_clash_round4 = Sha1Context::hash_clash_compress_round4_step;
        hash_clash_round4(&a, &mut b, &c, &d, &mut e, 60u8, &mut self.states.m1);
        hash_clash_round4(&e, &mut a, &b, &c, &mut d, 61u8, &mut self.states.m1);
        hash_clash_round4(&d, &mut e, &a, &b, &mut c, 62u8, &mut self.states.m1);
        hash_clash_round4(&c, &mut d, &e, &a, &mut b, 63u8, &mut self.states.m1);
        hash_clash_round4(&b, &mut c, &d, &e, &mut a, 64u8, &mut self.states.m1);
        hash_clash_round4(&a, &mut b, &c, &d, &mut e, 65u8, &mut self.states.m1);
        hash_clash_round4(&e, &mut a, &b, &c, &mut d, 66u8, &mut self.states.m1);
        hash_clash_round4(&d, &mut e, &a, &b, &mut c, 67u8, &mut self.states.m1);
        hash_clash_round4(&c, &mut d, &e, &a, &mut b, 68u8, &mut self.states.m1);
        hash_clash_round4(&b, &mut c, &d, &e, &mut a, 69u8, &mut self.states.m1);
        hash_clash_round4(&a, &mut b, &c, &d, &mut e, 70u8, &mut self.states.m1);
        hash_clash_round4(&e, &mut a, &b, &c, &mut d, 71u8, &mut self.states.m1);
        hash_clash_round4(&d, &mut e, &a, &b, &mut c, 72u8, &mut self.states.m1);
        hash_clash_round4(&c, &mut d, &e, &a, &mut b, 73u8, &mut self.states.m1);
        hash_clash_round4(&b, &mut c, &d, &e, &mut a, 74u8, &mut self.states.m1);
        hash_clash_round4(&a, &mut b, &c, &d, &mut e, 75u8, &mut self.states.m1);
        hash_clash_round4(&e, &mut a, &b, &c, &mut d, 76u8, &mut self.states.m1);
        hash_clash_round4(&d, &mut e, &a, &b, &mut c, 77u8, &mut self.states.m1);
        hash_clash_round4(&c, &mut d, &e, &a, &mut b, 78u8, &mut self.states.m1);
        hash_clash_round4(&b, &mut c, &d, &e, &mut a, 79u8, &mut self.states.m1);

        self.ihv[0] += a;
        self.ihv[1] += b;
        self.ihv[2] += c;
        self.ihv[3] += d;
        self.ihv[4] += e;
    }

    //TODO - Check later how to resume this process with iterators
    fn recompress_fast(
        &mut self,
        index: usize,
        ihv_temp: &mut [u32; 5],
        dvs: &[DisturbanceVectorInfo; 33],
    ) {
        let step = dvs[index].test_t as usize;
        let mut ihv_in: &mut [u32; 5] = &mut self.states.ihv2.clone();

        let mut a = self.states.states[step][0];
        let mut b = self.states.states[step][1];
        let mut c = self.states.states[step][2];
        let mut d = self.states.states[step][3];
        let mut e = self.states.states[step][4];

        self.recompress_first_process(step, &mut a, &mut b, &mut c, &mut d, &mut e);

        ihv_in[0] = a;
        ihv_in[1] = b;
        ihv_in[2] = c;
        ihv_in[3] = d;
        ihv_in[4] = e;
        a = self.states.states[step][0];
        b = self.states.states[step][1];
        c = self.states.states[step][2];
        d = self.states.states[step][3];
        e = self.states.states[step][4];

        self.recompress_second_process(step, &mut a, &mut b, &mut c, &mut d, &mut e);

        ihv_temp[0] = ihv_in[0] + a;
        ihv_temp[1] = ihv_in[1] + b;
        ihv_temp[2] = ihv_in[2] + c;
        ihv_temp[3] = ihv_in[3] + d;
        ihv_temp[4] = ihv_in[4] + e;

        self.states.states[step][0] = a;
        self.states.states[step][1] = b;
        self.states.states[step][2] = c;
        self.states.states[step][3] = d;
        self.states.states[step][4] = e;

        self.states.ihv2[0] = ihv_in[0];
        self.states.ihv2[1] = ihv_in[1];
        self.states.ihv2[2] = ihv_in[2];
        self.states.ihv2[3] = ihv_in[3];
        self.states.ihv2[4] = ihv_in[4];
    }

    fn recompress_first_process(
        &mut self,
        step: usize,
        mut a: &mut u32,
        mut b: &mut u32,
        mut c: &mut u32,
        mut d: &mut u32,
        mut e: &mut u32,
    ) {
        if (step > 79) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                79u8,
                &self.states.m2,
            );
        }
        if (step > 78) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                78u8,
                &self.states.m2,
            );
        }
        if (step > 77) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                77u8,
                &self.states.m2,
            );
        }
        if (step > 76) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                76u8,
                &self.states.m2,
            );
        }
        if (step > 75) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                75u8,
                &self.states.m2,
            );
        }
        if (step > 74) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                74u8,
                &self.states.m2,
            );
        }
        if (step > 73) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                73u8,
                &self.states.m2,
            );
        }
        if (step > 72) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                72u8,
                &self.states.m2,
            );
        }
        if (step > 71) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                71u8,
                &self.states.m2,
            );
        }
        if (step > 70) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                70u8,
                &self.states.m2,
            );
        }
        if (step > 69) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                69u8,
                &self.states.m2,
            );
        }
        if (step > 68) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                68u8,
                &self.states.m2,
            );
        }
        if (step > 67) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                67u8,
                &self.states.m2,
            );
        }
        if (step > 66) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                66u8,
                &self.states.m2,
            );
        }
        if (step > 65) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                65u8,
                &self.states.m2,
            );
        }
        if (step > 64) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                64u8,
                &self.states.m2,
            );
        }
        if (step > 63) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                63u8,
                &self.states.m2,
            );
        }
        if (step > 62) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                62u8,
                &self.states.m2,
            );
        }
        if (step > 61) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                61u8,
                &self.states.m2,
            );
        }
        if (step > 60) {
            Sha1Context::hash_clash_compress_round4_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                60u8,
                &self.states.m2,
            );
        }
        if (step > 59) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                59u8,
                &self.states.m2,
            );
        }
        if (step > 58) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                58u8,
                &self.states.m2,
            );
        }
        if (step > 57) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                57u8,
                &self.states.m2,
            );
        }
        if (step > 56) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                56u8,
                &self.states.m2,
            );
        }
        if (step > 55) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                55u8,
                &self.states.m2,
            );
        }
        if (step > 54) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                54u8,
                &self.states.m2,
            );
        }
        if (step > 53) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                53u8,
                &self.states.m2,
            );
        }
        if (step > 52) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                52u8,
                &self.states.m2,
            );
        }
        if (step > 51) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                51u8,
                &self.states.m2,
            );
        }
        if (step > 50) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                50u8,
                &self.states.m2,
            );
        }
        if (step > 49) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                49u8,
                &self.states.m2,
            );
        }
        if (step > 48) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                48u8,
                &self.states.m2,
            );
        }
        if (step > 47) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                47u8,
                &self.states.m2,
            );
        }
        if (step > 46) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                46u8,
                &self.states.m2,
            );
        }
        if (step > 45) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                45u8,
                &self.states.m2,
            );
        }
        if (step > 44) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                44u8,
                &self.states.m2,
            );
        }
        if (step > 43) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                43u8,
                &self.states.m2,
            );
        }
        if (step > 42) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                42u8,
                &self.states.m2,
            );
        }
        if (step > 41) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                41u8,
                &self.states.m2,
            );
        }
        if (step > 40) {
            Sha1Context::hash_clash_compress_round3_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                40u8,
                &self.states.m2,
            );
        }
        if (step > 39) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                39u8,
                &self.states.m2,
            );
        }
        if (step > 38) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                38u8,
                &self.states.m2,
            );
        }
        if (step > 37) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                37u8,
                &self.states.m2,
            );
        }
        if (step > 36) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                36u8,
                &self.states.m2,
            );
        }
        if (step > 35) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                35u8,
                &self.states.m2,
            );
        }
        if (step > 34) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                34u8,
                &self.states.m2,
            );
        }
        if (step > 33) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                33u8,
                &self.states.m2,
            );
        }
        if (step > 32) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                32u8,
                &self.states.m2,
            );
        }
        if (step > 31) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                31u8,
                &self.states.m2,
            );
        }
        if (step > 30) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                30u8,
                &self.states.m2,
            );
        }
        if (step > 29) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                29u8,
                &self.states.m2,
            );
        }
        if (step > 28) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                28u8,
                &self.states.m2,
            );
        }
        if (step > 27) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                27u8,
                &self.states.m2,
            );
        }
        if (step > 26) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                26u8,
                &self.states.m2,
            );
        }
        if (step > 25) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                25u8,
                &self.states.m2,
            );
        }
        if (step > 24) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                24u8,
                &self.states.m2,
            );
        }
        if (step > 23) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                23u8,
                &self.states.m2,
            );
        }
        if (step > 22) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                22u8,
                &self.states.m2,
            );
        }
        if (step > 21) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                21u8,
                &self.states.m2,
            );
        }
        if (step > 20) {
            Sha1Context::hash_clash_compress_round2_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                20u8,
                &self.states.m2,
            );
        }
        if (step > 19) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                19u8,
                &self.states.m2,
            );
        }
        if (step > 18) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                18u8,
                &self.states.m2,
            );
        }
        if (step > 17) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                17u8,
                &self.states.m2,
            );
        }
        if (step > 16) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                16u8,
                &self.states.m2,
            );
        }
        if (step > 15) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                15u8,
                &self.states.m2,
            );
        }
        if (step > 14) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                14u8,
                &self.states.m2,
            );
        }
        if (step > 13) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                13u8,
                &self.states.m2,
            );
        }
        if (step > 12) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                12u8,
                &self.states.m2,
            );
        }
        if (step > 11) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                11u8,
                &self.states.m2,
            );
        }
        if (step > 10) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                10u8,
                &self.states.m2,
            );
        }
        if (step > 9) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                9u8,
                &self.states.m2,
            );
        }
        if (step > 8) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                8u8,
                &self.states.m2,
            );
        }
        if (step > 7) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                7u8,
                &self.states.m2,
            );
        }
        if (step > 6) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                6u8,
                &self.states.m2,
            );
        }
        if (step > 5) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                5u8,
                &self.states.m2,
            );
        }
        if (step > 4) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                4u8,
                &self.states.m2,
            );
        }
        if (step > 3) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                3u8,
                &self.states.m2,
            );
        }
        if (step > 2) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                2u8,
                &self.states.m2,
            );
        }
        if (step > 1) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                1u8,
                &self.states.m2,
            );
        }
        if (step > 0) {
            Sha1Context::hash_clash_compress_round1_step_bw(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                0u8,
                &self.states.m2,
            );
        }
    }

    fn recompress_second_process(
        &self,
        step: usize,
        mut a: &mut u32,
        mut b: &mut u32,
        mut c: &mut u32,
        mut d: &mut u32,
        mut e: &mut u32,
    ) {
        if (step <= 0) {
            Sha1Context::hash_clash_compress_round1_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                0u8,
                &self.states.m2,
            );
        }
        if (step <= 1) {
            Sha1Context::hash_clash_compress_round1_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                1u8,
                &self.states.m2,
            );
        }
        if (step <= 2) {
            Sha1Context::hash_clash_compress_round1_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                2u8,
                &self.states.m2,
            );
        }
        if (step <= 3) {
            Sha1Context::hash_clash_compress_round1_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                3u8,
                &self.states.m2,
            );
        }
        if (step <= 4) {
            Sha1Context::hash_clash_compress_round1_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                4u8,
                &self.states.m2,
            );
        }
        if (step <= 5) {
            Sha1Context::hash_clash_compress_round1_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                5u8,
                &self.states.m2,
            );
        }
        if (step <= 6) {
            Sha1Context::hash_clash_compress_round1_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                6u8,
                &self.states.m2,
            );
        }
        if (step <= 7) {
            Sha1Context::hash_clash_compress_round1_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                7u8,
                &self.states.m2,
            );
        }
        if (step <= 8) {
            Sha1Context::hash_clash_compress_round1_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                8u8,
                &self.states.m2,
            );
        }
        if (step <= 9) {
            Sha1Context::hash_clash_compress_round1_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                9u8,
                &self.states.m2,
            );
        }
        if (step <= 10) {
            Sha1Context::hash_clash_compress_round1_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                10u8,
                &self.states.m2,
            );
        }
        if (step <= 11) {
            Sha1Context::hash_clash_compress_round1_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                11u8,
                &self.states.m2,
            );
        }
        if (step <= 12) {
            Sha1Context::hash_clash_compress_round1_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                12u8,
                &self.states.m2,
            );
        }
        if (step <= 13) {
            Sha1Context::hash_clash_compress_round1_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                13u8,
                &self.states.m2,
            );
        }
        if (step <= 14) {
            Sha1Context::hash_clash_compress_round1_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                14u8,
                &self.states.m2,
            );
        }
        if (step <= 15) {
            Sha1Context::hash_clash_compress_round1_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                15u8,
                &self.states.m2,
            );
        }
        if (step <= 16) {
            Sha1Context::hash_clash_compress_round1_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                16u8,
                &self.states.m2,
            );
        }
        if (step <= 17) {
            Sha1Context::hash_clash_compress_round1_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                17u8,
                &self.states.m2,
            );
        }
        if (step <= 18) {
            Sha1Context::hash_clash_compress_round1_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                18u8,
                &self.states.m2,
            );
        }
        if (step <= 19) {
            Sha1Context::hash_clash_compress_round1_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                19u8,
                &self.states.m2,
            );
        }
        if (step <= 20) {
            Sha1Context::hash_clash_compress_round2_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                20u8,
                &self.states.m2,
            );
        }
        if (step <= 21) {
            Sha1Context::hash_clash_compress_round2_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                21u8,
                &self.states.m2,
            );
        }
        if (step <= 22) {
            Sha1Context::hash_clash_compress_round2_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                22u8,
                &self.states.m2,
            );
        }
        if (step <= 23) {
            Sha1Context::hash_clash_compress_round2_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                23u8,
                &self.states.m2,
            );
        }
        if (step <= 24) {
            Sha1Context::hash_clash_compress_round2_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                24u8,
                &self.states.m2,
            );
        }
        if (step <= 25) {
            Sha1Context::hash_clash_compress_round2_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                25u8,
                &self.states.m2,
            );
        }
        if (step <= 26) {
            Sha1Context::hash_clash_compress_round2_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                26u8,
                &self.states.m2,
            );
        }
        if (step <= 27) {
            Sha1Context::hash_clash_compress_round2_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                27u8,
                &self.states.m2,
            );
        }
        if (step <= 28) {
            Sha1Context::hash_clash_compress_round2_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                28u8,
                &self.states.m2,
            );
        }
        if (step <= 29) {
            Sha1Context::hash_clash_compress_round2_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                29u8,
                &self.states.m2,
            );
        }
        if (step <= 30) {
            Sha1Context::hash_clash_compress_round2_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                30u8,
                &self.states.m2,
            );
        }
        if (step <= 31) {
            Sha1Context::hash_clash_compress_round2_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                31u8,
                &self.states.m2,
            );
        }
        if (step <= 32) {
            Sha1Context::hash_clash_compress_round2_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                32u8,
                &self.states.m2,
            );
        }
        if (step <= 33) {
            Sha1Context::hash_clash_compress_round2_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                33u8,
                &self.states.m2,
            );
        }
        if (step <= 34) {
            Sha1Context::hash_clash_compress_round2_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                34u8,
                &self.states.m2,
            );
        }
        if (step <= 35) {
            Sha1Context::hash_clash_compress_round2_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                35u8,
                &self.states.m2,
            );
        }
        if (step <= 36) {
            Sha1Context::hash_clash_compress_round2_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                36u8,
                &self.states.m2,
            );
        }
        if (step <= 37) {
            Sha1Context::hash_clash_compress_round2_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                37u8,
                &self.states.m2,
            );
        }
        if (step <= 38) {
            Sha1Context::hash_clash_compress_round2_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                38u8,
                &self.states.m2,
            );
        }
        if (step <= 39) {
            Sha1Context::hash_clash_compress_round2_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                39u8,
                &self.states.m2,
            );
        }
        if (step <= 40) {
            Sha1Context::hash_clash_compress_round3_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                40u8,
                &self.states.m2,
            );
        }
        if (step <= 41) {
            Sha1Context::hash_clash_compress_round3_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                41u8,
                &self.states.m2,
            );
        }
        if (step <= 42) {
            Sha1Context::hash_clash_compress_round3_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                42u8,
                &self.states.m2,
            );
        }
        if (step <= 43) {
            Sha1Context::hash_clash_compress_round3_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                43u8,
                &self.states.m2,
            );
        }
        if (step <= 44) {
            Sha1Context::hash_clash_compress_round3_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                44u8,
                &self.states.m2,
            );
        }
        if (step <= 45) {
            Sha1Context::hash_clash_compress_round3_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                45u8,
                &self.states.m2,
            );
        }
        if (step <= 46) {
            Sha1Context::hash_clash_compress_round3_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                46u8,
                &self.states.m2,
            );
        }
        if (step <= 47) {
            Sha1Context::hash_clash_compress_round3_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                47u8,
                &self.states.m2,
            );
        }
        if (step <= 48) {
            Sha1Context::hash_clash_compress_round3_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                48u8,
                &self.states.m2,
            );
        }
        if (step <= 49) {
            Sha1Context::hash_clash_compress_round3_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                49u8,
                &self.states.m2,
            );
        }
        if (step <= 50) {
            Sha1Context::hash_clash_compress_round3_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                50u8,
                &self.states.m2,
            );
        }
        if (step <= 51) {
            Sha1Context::hash_clash_compress_round3_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                51u8,
                &self.states.m2,
            );
        }
        if (step <= 52) {
            Sha1Context::hash_clash_compress_round3_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                52u8,
                &self.states.m2,
            );
        }
        if (step <= 53) {
            Sha1Context::hash_clash_compress_round3_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                53u8,
                &self.states.m2,
            );
        }
        if (step <= 54) {
            Sha1Context::hash_clash_compress_round3_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                54u8,
                &self.states.m2,
            );
        }
        if (step <= 55) {
            Sha1Context::hash_clash_compress_round3_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                55u8,
                &self.states.m2,
            );
        }
        if (step <= 56) {
            Sha1Context::hash_clash_compress_round3_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                56u8,
                &self.states.m2,
            );
        }
        if (step <= 57) {
            Sha1Context::hash_clash_compress_round3_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                57u8,
                &self.states.m2,
            );
        }
        if (step <= 58) {
            Sha1Context::hash_clash_compress_round3_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                58u8,
                &self.states.m2,
            );
        }
        if (step <= 59) {
            Sha1Context::hash_clash_compress_round3_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                59u8,
                &self.states.m2,
            );
        }
        if (step <= 60) {
            Sha1Context::hash_clash_compress_round4_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                60u8,
                &self.states.m2,
            );
        }
        if (step <= 61) {
            Sha1Context::hash_clash_compress_round4_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                61u8,
                &self.states.m2,
            );
        }
        if (step <= 62) {
            Sha1Context::hash_clash_compress_round4_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                62u8,
                &self.states.m2,
            );
        }
        if (step <= 63) {
            Sha1Context::hash_clash_compress_round4_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                63u8,
                &self.states.m2,
            );
        }
        if (step <= 64) {
            Sha1Context::hash_clash_compress_round4_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                64u8,
                &self.states.m2,
            );
        }
        if (step <= 65) {
            Sha1Context::hash_clash_compress_round4_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                65u8,
                &self.states.m2,
            );
        }
        if (step <= 66) {
            Sha1Context::hash_clash_compress_round4_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                66u8,
                &self.states.m2,
            );
        }
        if (step <= 67) {
            Sha1Context::hash_clash_compress_round4_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                67u8,
                &self.states.m2,
            );
        }
        if (step <= 68) {
            Sha1Context::hash_clash_compress_round4_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                68u8,
                &self.states.m2,
            );
        }
        if (step <= 69) {
            Sha1Context::hash_clash_compress_round4_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                69u8,
                &self.states.m2,
            );
        }
        if (step <= 70) {
            Sha1Context::hash_clash_compress_round4_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                70u8,
                &self.states.m2,
            );
        }
        if (step <= 71) {
            Sha1Context::hash_clash_compress_round4_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                71u8,
                &self.states.m2,
            );
        }
        if (step <= 72) {
            Sha1Context::hash_clash_compress_round4_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                72u8,
                &self.states.m2,
            );
        }
        if (step <= 73) {
            Sha1Context::hash_clash_compress_round4_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                73u8,
                &self.states.m2,
            );
        }
        if (step <= 74) {
            Sha1Context::hash_clash_compress_round4_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                74u8,
                &self.states.m2,
            );
        }
        if (step <= 75) {
            Sha1Context::hash_clash_compress_round4_step(
                &a,
                &mut b,
                &c,
                &d,
                &mut e,
                75u8,
                &self.states.m2,
            );
        }
        if (step <= 76) {
            Sha1Context::hash_clash_compress_round4_step(
                &e,
                &mut a,
                &b,
                &c,
                &mut d,
                76u8,
                &self.states.m2,
            );
        }
        if (step <= 77) {
            Sha1Context::hash_clash_compress_round4_step(
                &d,
                &mut e,
                &a,
                &b,
                &mut c,
                77u8,
                &self.states.m2,
            );
        }
        if (step <= 78) {
            Sha1Context::hash_clash_compress_round4_step(
                &c,
                &mut d,
                &e,
                &a,
                &mut b,
                78u8,
                &self.states.m2,
            );
        }
        if (step <= 79) {
            Sha1Context::hash_clash_compress_round4_step(
                &b,
                &mut c,
                &d,
                &e,
                &mut a,
                79u8,
                &self.states.m2,
            );
        }
    }
}
