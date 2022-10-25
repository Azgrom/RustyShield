use core::ops::{BitOr, Shl, Shr};

fn main() {
    println!("Hello, world!");
}

const T_0_15: u32 = 0x5a827999;
const T_16_19: u32 = T_0_15;
const T_20_39: u32 = 0x6ed9eba1;
const T_40_59: u32 = 0x8f1bbcdc;
const T_60_79: u32 = 0xca62c1d6;
const U8_TO_U32: [u8; 4] = [0, 8, 16, 24];

trait ShiftSideways:
    Shl<Output = Self> + Shr<Output = Self> + BitOr<Output = Self> + Copy + Sized
{
}

impl ShiftSideways for u32 {}

fn rotate<R: ShiftSideways>(x: R, l: R, r: R) -> R {
    (x << l) | (x >> r)
}

fn rotate_left(x: u32, n: u32) -> u32 {
    rotate(x, n, 32 - n)
}

fn rotate_right(x: u32, n: u32) -> u32 {
    rotate(x, 32 - n, n)
}

trait Sha1 {
    fn init(&mut self);
    // TODO: fn update(&mut self, data_in: &[u8], len: usize);
    fn finalize(&mut self) -> [u8; 20];
}

struct ShaContext {
    size: usize,
    h: [u32; 5],
    w: [u32; 16]
}

trait MemoryCopy<S, D> {
    /// Copies n bytes from src to memory dest, using a reference receiving point in dest
    fn mem_cpy(src: &[S], dest: &mut [D], src_slice_len: usize, dest_offset:usize);
}

trait ShaSource<T> {
    fn src(i: usize, v: &[T]) -> u32;
    fn t_0_15(s: &mut ShaContext, t: u8, block: &[T], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, array: &mut [u32]);
    fn block(s: &mut ShaContext, block: &[T]);
    fn update(&mut self, data_in: &[T], len: usize);
}

impl MemoryCopy<u8, u8> for ShaContext {
    fn mem_cpy(src: &[u8], dest: &mut [u8], src_slice_len: usize, dest_offset: usize) {
        dest[dest_offset..].clone_from_slice(&src[..src_slice_len])
    }
}

impl MemoryCopy<u8, u32> for ShaContext {
    fn mem_cpy(src: &[u8], dest: &mut [u32], src_slice_len: usize, dest_offset: usize) {
        // TODO: this impl considers src and src_len larger than 4 bytes. Implement flows for lesser cases
        let mut src_i = src_slice_len;
        dest[dest_offset..].iter_mut().for_each(|e| {
            *e = (src[src_i] as u32) | ((src[src_i + 1] as u32) << 8) | ((src[src_i + 2] as u32) << 16) | ((src[src_i + 3] as u32) << 24);
            src_i += 1;
        })
    }
}

impl MemoryCopy<u32, u32> for ShaContext {
    fn mem_cpy(src: &[u32], dest: &mut [u32], src_slice_len: usize, dest_offset: usize) {
        dest[dest_offset..].clone_from_slice(&src[..src_slice_len])
    }
}

impl ShaSource<u8> for ShaContext {
    fn src(i: usize, v: &[u8]) -> u32 {
        // TODO: See if there should have validation here
        let s = i * 4;
        ((v[s] as u32) << 24)
            | ((v[s + 1] as u32) << 16)
            | ((v[s + 2] as u32) << 8)
            | (v[s + 3] as u32)
    }

    fn t_0_15(s: &mut ShaContext, t: u8, block: &[u8], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, array: &mut [u32])  {
        let temp = Self::src(t as usize, block);
        Self::set_w(t as usize, temp, array);
        *e += temp + rotate_left(a, 5) + Self::f1(*b, c, d) + T_0_15;
        *b = rotate_right(*b, 2);
    }

    fn block(s: &mut ShaContext, block: &[u8]) {
        let mut a = s.h[0];
        let mut b = s.h[1];
        let mut c = s.h[2];
        let mut d = s.h[3];
        let mut e = s.h[4];

        let mut array: [u32; 16] = [0; 16];

        /* Round 1 - iterations 0-16 take their input from 'block' */
        Self::t_0_15(s, 0, block, a, &mut b, c, d, &mut e, &mut array);
        Self::t_0_15(s, 1, block, e, &mut a, b, c, &mut d, &mut array);
        Self::t_0_15(s, 2, block, d, &mut e, a, b, &mut c, &mut array);
        Self::t_0_15(s, 3, block, c, &mut d, e, a, &mut b, &mut array);
        Self::t_0_15(s, 4, block, b, &mut c, d, e, &mut a, &mut array);
        Self::t_0_15(s, 5, block, a, &mut b, c, d, &mut e, &mut array);
        Self::t_0_15(s, 6, block, e, &mut a, b, c, &mut d, &mut array);
        Self::t_0_15(s, 7, block, d, &mut e, a, b, &mut c, &mut array);
        Self::t_0_15(s, 8, block, c, &mut d, e, a, &mut b, &mut array);
        Self::t_0_15(s, 9, block, b, &mut c, d, e, &mut a, &mut array);
        Self::t_0_15(s, 10, block, a,&mut  b, c, d,&mut  e, &mut array);
        Self::t_0_15(s, 11, block, e,&mut  a, b, c,&mut  d, &mut array);
        Self::t_0_15(s, 12, block, d,&mut  e, a, b,&mut  c, &mut array);
        Self::t_0_15(s, 13, block, c,&mut  d, e, a,&mut  b, &mut array);
        Self::t_0_15(s, 14, block, b,&mut  c, d, e,&mut  a, &mut array);
        Self::t_0_15(s, 15, block, a,&mut  b, c, d,&mut  e, &mut array);

        /* Round 1 - tail. Input from 512-bit mixing array */
        Self::t_16_19(s, 16, &mut array, e, &mut a, b, c, &mut d);
        Self::t_16_19(s, 17, &mut array, d, &mut e, a, b, &mut c);
        Self::t_16_19(s, 18, &mut array, c, &mut d, e, a, &mut b);
        Self::t_16_19(s, 19, &mut array, b, &mut c, d, e, &mut a);

        /* Round 2 */
        Self::t_20_39(s, 20, &mut array, a, b, c, d, e);
        Self::t_20_39(s, 21, &mut array, e, a, b, c, d);
        Self::t_20_39(s, 22, &mut array, d, e, a, b, c);
        Self::t_20_39(s, 23, &mut array, c, d, e, a, b);
        Self::t_20_39(s, 24, &mut array, b, c, d, e, a);
        Self::t_20_39(s, 25, &mut array, a, b, c, d, e);
        Self::t_20_39(s, 26, &mut array, e, a, b, c, d);
        Self::t_20_39(s, 27, &mut array, d, e, a, b, c);
        Self::t_20_39(s, 28, &mut array, c, d, e, a, b);
        Self::t_20_39(s, 29, &mut array, b, c, d, e, a);
        Self::t_20_39(s, 30, &mut array, a, b, c, d, e);
        Self::t_20_39(s, 31, &mut array, e, a, b, c, d);
        Self::t_20_39(s, 32, &mut array, d, e, a, b, c);
        Self::t_20_39(s, 33, &mut array, c, d, e, a, b);
        Self::t_20_39(s, 34, &mut array, b, c, d, e, a);
        Self::t_20_39(s, 35, &mut array, a, b, c, d, e);
        Self::t_20_39(s, 36, &mut array, e, a, b, c, d);
        Self::t_20_39(s, 37, &mut array, d, e, a, b, c);
        Self::t_20_39(s, 38, &mut array, c, d, e, a, b);
        Self::t_20_39(s, 39, &mut array, b, c, d, e, a);

        /* Round 3 */
        Self::t_40_59(s, 40, &mut array, a, b, c, d, e);
        Self::t_40_59(s, 41, &mut array, e, a, b, c, d);
        Self::t_40_59(s, 42, &mut array, d, e, a, b, c);
        Self::t_40_59(s, 43, &mut array, c, d, e, a, b);
        Self::t_40_59(s, 44, &mut array, b, c, d, e, a);
        Self::t_40_59(s, 45, &mut array, a, b, c, d, e);
        Self::t_40_59(s, 46, &mut array, e, a, b, c, d);
        Self::t_40_59(s, 47, &mut array, d, e, a, b, c);
        Self::t_40_59(s, 48, &mut array, c, d, e, a, b);
        Self::t_40_59(s, 49, &mut array, b, c, d, e, a);
        Self::t_40_59(s, 50, &mut array, a, b, c, d, e);
        Self::t_40_59(s, 51, &mut array, e, a, b, c, d);
        Self::t_40_59(s, 52, &mut array, d, e, a, b, c);
        Self::t_40_59(s, 53, &mut array, c, d, e, a, b);
        Self::t_40_59(s, 54, &mut array, b, c, d, e, a);
        Self::t_40_59(s, 55, &mut array, a, b, c, d, e);
        Self::t_40_59(s, 56, &mut array, e, a, b, c, d);
        Self::t_40_59(s, 57, &mut array, d, e, a, b, c);
        Self::t_40_59(s, 58, &mut array, c, d, e, a, b);
        Self::t_40_59(s, 59, &mut array, b, c, d, e, a);

        /* Round 4 */
        Self::t_60_79(s, 60, &mut array, a, b, c, d, e);
        Self::t_60_79(s, 61, &mut array, e, a, b, c, d);
        Self::t_60_79(s, 62, &mut array, d, e, a, b, c);
        Self::t_60_79(s, 63, &mut array, c, d, e, a, b);
        Self::t_60_79(s, 64, &mut array, b, c, d, e, a);
        Self::t_60_79(s, 65, &mut array, a, b, c, d, e);
        Self::t_60_79(s, 66, &mut array, e, a, b, c, d);
        Self::t_60_79(s, 67, &mut array, d, e, a, b, c);
        Self::t_60_79(s, 68, &mut array, c, d, e, a, b);
        Self::t_60_79(s, 69, &mut array, b, c, d, e, a);
        Self::t_60_79(s, 70, &mut array, a, b, c, d, e);
        Self::t_60_79(s, 71, &mut array, e, a, b, c, d);
        Self::t_60_79(s, 72, &mut array, d, e, a, b, c);
        Self::t_60_79(s, 73, &mut array, c, d, e, a, b);
        Self::t_60_79(s, 74, &mut array, b, c, d, e, a);
        Self::t_60_79(s, 75, &mut array, a, b, c, d, e);
        Self::t_60_79(s, 76, &mut array, e, a, b, c, d);
        Self::t_60_79(s, 77, &mut array, d, e, a, b, c);
        Self::t_60_79(s, 78, &mut array, c, d, e, a, b);
        Self::t_60_79(s, 79, &mut array, b, c, d, e, a);

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
    }

    fn update(&mut self, data_in: &[u8], mut len: usize) {
        let mut data: &[u8] = &Vec::new();
        let mut len_w = self.size & 63;

        self.size += len;

        if len_w > 0 {
            let mut left = 64 - len_w;
            if len < left {
                left = len;
            }

            Self::mem_cpy(data_in, &mut self.w, left, len_w);

            len_w = (len_w + left) & 63;
            len -= left;
            data = &data_in[left..];

            if len_w > 0 {
                return;
            }

            Self::block(self, &mut self.w);
        }

        while len >= 64 {
            Self::block(self, data);
            data = &data[64..];
            len -= 64;
        }

        if len > 0 {
            Self::mem_cpy(data, &mut self.w, len, 0);
        }
    }
}

impl ShaSource<u32> for ShaContext {
    fn src(i: usize, v: &[u32]) -> u32 {
        v[i].to_be()
    }

    fn t_0_15(s: &mut ShaContext, t: u8, block: &[u32], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, array: &mut [u32]) {
        todo!()
    }

    fn block(s: &mut ShaContext, block: &[u32]) {
        let mut a = s.h[0];
        let mut b = s.h[1];
        let mut c = s.h[2];
        let mut d = s.h[3];
        let mut e = s.h[4];

        let mut array: [u32; 16] = [0; 16];

        /* Round 1 - iterations 0-16 take their input from 'block' */
        Self::t_0_15(s, 0, block, a, &mut b, c, d, &mut e, &mut array);
        Self::t_0_15(s, 1, block, e, &mut a, b, c, &mut d, &mut array);
        Self::t_0_15(s, 2, block, d, &mut e, a, b, &mut c, &mut array);
        Self::t_0_15(s, 3, block, c, &mut d, e, a, &mut b, &mut array);
        Self::t_0_15(s, 4, block, b, &mut c, d, e, &mut a, &mut array);
        Self::t_0_15(s, 5, block, a, &mut b, c, d, &mut e, &mut array);
        Self::t_0_15(s, 6, block, e, &mut a, b, c, &mut d, &mut array);
        Self::t_0_15(s, 7, block, d, &mut e, a, b, &mut c, &mut array);
        Self::t_0_15(s, 8, block, c, &mut d, e, a, &mut b, &mut array);
        Self::t_0_15(s, 9, block, b, &mut c, d, e, &mut a, &mut array);
        Self::t_0_15(s, 10, block, a,&mut  b, c, d,&mut  e, &mut array);
        Self::t_0_15(s, 11, block, e,&mut  a, b, c,&mut  d, &mut array);
        Self::t_0_15(s, 12, block, d,&mut  e, a, b,&mut  c, &mut array);
        Self::t_0_15(s, 13, block, c,&mut  d, e, a,&mut  b, &mut array);
        Self::t_0_15(s, 14, block, b,&mut  c, d, e,&mut  a, &mut array);
        Self::t_0_15(s, 15, block, a,&mut  b, c, d,&mut  e, &mut array);

        /* Round 1 - tail. Input from 512-bit mixing array */
        Self::t_16_19(s, 16, &mut array, e, &mut a, b, c, &mut d);
        Self::t_16_19(s, 17, &mut array, d, &mut e, a, b, &mut c);
        Self::t_16_19(s, 18, &mut array, c, &mut d, e, a, &mut b);
        Self::t_16_19(s, 19, &mut array, b, &mut c, d, e, &mut a);

        /* Round 2 */
        Self::t_20_39(s, 20, &mut array, a, b, c, d, e);
        Self::t_20_39(s, 21, &mut array, e, a, b, c, d);
        Self::t_20_39(s, 22, &mut array, d, e, a, b, c);
        Self::t_20_39(s, 23, &mut array, c, d, e, a, b);
        Self::t_20_39(s, 24, &mut array, b, c, d, e, a);
        Self::t_20_39(s, 25, &mut array, a, b, c, d, e);
        Self::t_20_39(s, 26, &mut array, e, a, b, c, d);
        Self::t_20_39(s, 27, &mut array, d, e, a, b, c);
        Self::t_20_39(s, 28, &mut array, c, d, e, a, b);
        Self::t_20_39(s, 29, &mut array, b, c, d, e, a);
        Self::t_20_39(s, 30, &mut array, a, b, c, d, e);
        Self::t_20_39(s, 31, &mut array, e, a, b, c, d);
        Self::t_20_39(s, 32, &mut array, d, e, a, b, c);
        Self::t_20_39(s, 33, &mut array, c, d, e, a, b);
        Self::t_20_39(s, 34, &mut array, b, c, d, e, a);
        Self::t_20_39(s, 35, &mut array, a, b, c, d, e);
        Self::t_20_39(s, 36, &mut array, e, a, b, c, d);
        Self::t_20_39(s, 37, &mut array, d, e, a, b, c);
        Self::t_20_39(s, 38, &mut array, c, d, e, a, b);
        Self::t_20_39(s, 39, &mut array, b, c, d, e, a);

        /* Round 3 */
        Self::t_40_59(s, 40, &mut array, a, b, c, d, e);
        Self::t_40_59(s, 41, &mut array, e, a, b, c, d);
        Self::t_40_59(s, 42, &mut array, d, e, a, b, c);
        Self::t_40_59(s, 43, &mut array, c, d, e, a, b);
        Self::t_40_59(s, 44, &mut array, b, c, d, e, a);
        Self::t_40_59(s, 45, &mut array, a, b, c, d, e);
        Self::t_40_59(s, 46, &mut array, e, a, b, c, d);
        Self::t_40_59(s, 47, &mut array, d, e, a, b, c);
        Self::t_40_59(s, 48, &mut array, c, d, e, a, b);
        Self::t_40_59(s, 49, &mut array, b, c, d, e, a);
        Self::t_40_59(s, 50, &mut array, a, b, c, d, e);
        Self::t_40_59(s, 51, &mut array, e, a, b, c, d);
        Self::t_40_59(s, 52, &mut array, d, e, a, b, c);
        Self::t_40_59(s, 53, &mut array, c, d, e, a, b);
        Self::t_40_59(s, 54, &mut array, b, c, d, e, a);
        Self::t_40_59(s, 55, &mut array, a, b, c, d, e);
        Self::t_40_59(s, 56, &mut array, e, a, b, c, d);
        Self::t_40_59(s, 57, &mut array, d, e, a, b, c);
        Self::t_40_59(s, 58, &mut array, c, d, e, a, b);
        Self::t_40_59(s, 59, &mut array, b, c, d, e, a);

        /* Round 4 */
        Self::t_60_79(s, 60, &mut array, a, b, c, d, e);
        Self::t_60_79(s, 61, &mut array, e, a, b, c, d);
        Self::t_60_79(s, 62, &mut array, d, e, a, b, c);
        Self::t_60_79(s, 63, &mut array, c, d, e, a, b);
        Self::t_60_79(s, 64, &mut array, b, c, d, e, a);
        Self::t_60_79(s, 65, &mut array, a, b, c, d, e);
        Self::t_60_79(s, 66, &mut array, e, a, b, c, d);
        Self::t_60_79(s, 67, &mut array, d, e, a, b, c);
        Self::t_60_79(s, 68, &mut array, c, d, e, a, b);
        Self::t_60_79(s, 69, &mut array, b, c, d, e, a);
        Self::t_60_79(s, 70, &mut array, a, b, c, d, e);
        Self::t_60_79(s, 71, &mut array, e, a, b, c, d);
        Self::t_60_79(s, 72, &mut array, d, e, a, b, c);
        Self::t_60_79(s, 73, &mut array, c, d, e, a, b);
        Self::t_60_79(s, 74, &mut array, b, c, d, e, a);
        Self::t_60_79(s, 75, &mut array, a, b, c, d, e);
        Self::t_60_79(s, 76, &mut array, e, a, b, c, d);
        Self::t_60_79(s, 77, &mut array, d, e, a, b, c);
        Self::t_60_79(s, 78, &mut array, c, d, e, a, b);
        Self::t_60_79(s, 79, &mut array, b, c, d, e, a);

        s.h[0] = s.h[0].wrapping_add(a);
        s.h[1] = s.h[1].wrapping_add(b);
        s.h[2] = s.h[2].wrapping_add(c);
        s.h[3] = s.h[3].wrapping_add(d);
        s.h[4] = s.h[4].wrapping_add(e);
    }

    fn update(&mut self, data_in: &[u32], mut len: usize) {
        let mut data: &[u32] = &Vec::new();
        let mut len_w = self.size & 63;

        self.size += len;

        if len_w > 0 {
            let mut left = 64 - len_w;
            if len < left {
                left = len;
            }

            Self::mem_cpy(data_in, &mut self.w, left, len_w);

            len_w = (len_w + left) & 63;
            len -= left;
            data = &data_in[left..];

            if len_w > 0 {
                return;
            }

            Self::block(self, &mut self.w);
        }

        while len >= 64 {
            Self::block(self, data);
            data = &data[64..];
            len -= 64;
        }

        if len > 0 {
            Self::mem_cpy(data, &mut self.w, len, 0);
        }
    }
}

impl ShaContext {
    fn set_w(i: usize, val: u32, array: &mut [u32]) {
        array[i & 15] = val;
    }

    fn mix(i: usize, array: &[u32]) -> u32 {
        let x = array[i + 13];
        let y = array[i + 8];
        let z = array[i + 2];
        let t = array[i];

        rotate_left(x ^ y ^ z ^ t, 1)
    }

    fn f1(b: u32, c: u32, d: u32) -> u32 {
        ((c ^ d) & b) ^ d
    }

    fn f2(b: u32, c: u32, d: u32) -> u32 {
        b ^ c ^ d
    }

    fn f3(b: u32, c: u32, d: u32) -> u32 {
        (b & c) + (d & (b ^ c))
    }

    fn f4(b: u32, c: u32, d: u32) -> u32 {
        Self::f2(b, c, d)
    }

    fn zero_first_twenty_four_bits(h: &u32) -> u8 {
        ((*h << 24) >> 24) as u8
    }

    fn round(
        &mut self,
        t: u8,
        block: &mut [u32],
        f_n: u32,
        constant: u32,
        a: u32,
        b: &mut u32,
        c: u32,
        d: u32,
        e: &mut u32,
    ) {
        let temp = Self::mix(t as usize, block);
        Self::set_w(t as usize, temp, block);
        *e += temp + rotate_left(a, 5) + f_n + constant;
        *b = rotate_right(*b, 2);
    }

    fn t_16_19(s: &mut ShaContext, t: u8, shamble_arr: &mut [u32], a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32) {
        s.round(
            t,
            shamble_arr,
            Self::f1(*b, c, d),
            T_16_19,
            a,
            b,
            c,
            d,
            e,
        )
    }

    fn t_20_39(s: &mut ShaContext, t: u8, shamble_arr: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        s.round(
            t,
            shamble_arr,
            Self::f2(b, c, d),
            T_20_39,
            a,
            &mut b,
            c,
            d,
            &mut e,
        )
    }

    fn t_40_59(s: &mut ShaContext, t: u8, shamble_arr: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        s.round(
            t,
            shamble_arr,
            Self::f3(b, c, d),
            T_40_59,
            a,
            &mut b,
            c,
            d,
            &mut e,
        )
    }

    fn t_60_79(s: &mut ShaContext, t: u8, shamble_arr: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        s.round(
            t,
            shamble_arr,
            Self::f4(b, c, d),
            T_60_79,
            a,
            &mut b,
            c,
            d,
            &mut e,
        )
    }
}

impl Sha1 for ShaContext {
    fn init(&mut self) {
        self.size = 0;

        /* Initialize H with the magic constants (see FIPS180 for constants) */
        self.h[0] = 0x67452301;
        self.h[1] = 0xefcdab89;
        self.h[2] = 0x98badcfe;
        self.h[3] = 0x10325476;
        self.h[4] = 0xc3d2e1f0;
    }

    fn finalize(&mut self) -> [u8; 20] {
        let mut pad: [u8; 64] = [0; 64];
        let mut pad_len: [u32; 2]= [0; 2];
        pad[0] = 0x80;

        let i = self.size & 63;
        self.update(&pad, 1 + (63 & (55 - i)));
        self.update(&pad_len, 8);

        let mut hash_out: [u8; 20] = [0; 20];

        self.h.iter().zip((0..5).into_iter()).for_each(|(h, i)| {
            hash_out[0 + (i * 4)] = (*h >> 24) as u8;
            hash_out[1 + (i * 4)] = (*h >> 16) as u8;
            hash_out[2 + (i * 4)] = (*h >> 8) as u8;
            hash_out[3 + (i * 4)] = Self::zero_first_twenty_four_bits(h);
        });

        return hash_out;
    }
}

#[cfg(test)]
mod test {
    use crate::{rotate_left, rotate_right, ShaContext};

    #[test]
    fn custom_right_bit_rotation_should_return_same_as_standard_impl() {
        let x: u32 = 5;
        let y: u32 = 2;
        let std_rotate_right = x.rotate_right(y);
        let cus_rotate_right = rotate_right(x, y);

        assert_eq!(std_rotate_right, cus_rotate_right);
    }

    #[test]
    fn custom_left_bit_rotation_should_return_same_as_standard_impl() {
        let x: u32 = 5;
        let y: u32 = 2;
        let std_rotate_left = x.rotate_left(y);
        let cus_rotate_left = rotate_left(x, y);

        assert_eq!(std_rotate_left, cus_rotate_left);
    }
}

fn swab32(val: &u32) -> u32 {
    ((*val & 0xff000000) >> 24)
        | ((*val & 0x00ff0000) >> 8)
        | ((*val & 0x0000ff00) << 8)
        | ((*val & 0x000000ff) << 24)
}
