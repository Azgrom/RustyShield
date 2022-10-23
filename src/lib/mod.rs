use core::ops::{Add, BitAnd, BitOr, BitXor, Index, IndexMut, Shl, Shr};

fn main() {
    println!("Hello, world!");
}

const T_0_19: u32 = 0x5a827999;
const T_20_39: u32 = 0x6ed9eba1;
const T_40_59: u32 = 0x8f1bbcdc;
const T_60_79: u32 = 0xca62c1d6;

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
    fn init(&self);
    fn update(&self, data_in: &[u8], len: usize);
    fn finalize(&self) -> [u8; 20];
}

struct W {
    data: [u32; 16],
}

impl Index<usize> for W {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index & 15]
    }
}

impl IndexMut<usize> for W {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index & 15]
    }
}

struct ShaContext {
    size: usize,
    h: [u32; 5],
    w: W,
}

trait ShaSource<T> {
    fn src(i: usize, v: &[T]) -> u32;
}

impl ShaSource<u8> for ShaContext {
    fn src(i: usize, v: &[u8]) -> u32 {
        // TODO: See if there should have validation here
        let s = i * 4;
        ((v[s] as u32) << 24)
            | ((v[s + 1] as u32) << 16)
            | ((v[s + 2] as u32) << 8)
            | ((v[s + 3] as u32) << 0)
    }
}

impl ShaSource<u32> for ShaContext {
    fn src(i: usize, v: &[u32]) -> u32 {
        v[i].to_be()
    }
}

impl ShaContext {
    fn set_w(i: usize, val: u32, array: &mut [u32]) {
        array[i] = val;
    }

    fn mix(&mut self, i: usize) -> u32 {
        let x = self.w[i + 13];
        let y = self.w[i + 8];
        let z = self.w[i + 2];
        let t = self.w[i];

        rotate_left(x ^ y ^ z ^ t, 1)
    }

    fn f_1(b: u32, c: u32, d: u32) -> u32 {
        ((c ^ d) & b) ^ d
    }

    fn f_2(b: u32, c: u32, d: u32) -> u32 {
        b ^ c ^ d
    }

    fn f_3(b: u32, c: u32, d: u32) -> u32 {
        (b & c) + (d & (b ^ c))
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
        let temp = self.mix(t as usize);
        Self::set_w(t as usize, temp, block);
        *e += temp + rotate_left(a, 5) + f_n + constant;
        *b = rotate_right(*b, 2);
    }

    fn t_0_15(&mut self, t: u8, block: &[u8], a: u32, mut b: u32, c: u32, d: u32, mut e: u32, array: &mut [u32])  {
        let temp = Self::src(t as usize, block);
        Self::set_w(t as usize, temp, array);
        *e += temp + rotate_left(a, 5) + f_n + constant;
        *b = rotate_right(*b, 2);
    }

    fn t_16_19(&mut self, t: u8, block: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        <ShaContext as ShaRound<Mix>>::round(
            self,
            t,
            block,
            Self::f_1(b, c, d),
            T_0_19,
            a,
            &mut b,
            c,
            d,
            &mut e,
        )
    }

    fn t_20_39(&mut self, t: u8, block: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        <ShaContext as ShaRound<Mix>>::round(
            self,
            t,
            block,
            Self::f_2(b, c, d),
            T_20_39,
            a,
            &mut b,
            c,
            d,
            &mut e,
        )
    }

    fn t_40_59(&mut self, t: u8, block: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        <ShaContext as ShaRound<Mix>>::round(
            self,
            t,
            block,
            Self::f_3(b, c, d),
            T_40_59,
            a,
            &mut b,
            c,
            d,
            &mut e,
        )
    }

    fn t_60_79(&mut self, t: u8, block: &mut [u32], a: u32, mut b: u32, c: u32, d: u32, mut e: u32) {
        <ShaContext as ShaRound<Mix>>::round(
            self,
            t,
            block,
            Self::f_2(b, c, d),
            T_60_79,
            a,
            &mut b,
            c,
            d,
            &mut e,
        )
    }

    fn block(&mut self, block: &[u8]) {
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        let mut array: &[u32] = vec![0; 16].as_slice();

        /* Round 1 - iterations 0-16 take their input from 'block' */
        self.t_0_15(0, block, a, b, c, d, e, &mut array);
        self.t_0_15(1, block, e, a, b, c, d, &mut array);
        self.t_0_15(2, block, d, e, a, b, c, &mut array);
        self.t_0_15(3, block, c, d, e, a, b, &mut array);
        self.t_0_15(4, block, b, c, d, e, a, &mut array);
        self.t_0_15(5, block, a, b, c, d, e, &mut array);
        self.t_0_15(6, block, e, a, b, c, d, &mut array);
        self.t_0_15(7, block, d, e, a, b, c, &mut array);
        self.t_0_15(8, block, c, d, e, a, b, &mut array);
        self.t_0_15(9, block, b, c, d, e, a, &mut array);
        self.t_0_15(10, block, a, b, c, d, e, &mut array);
        self.t_0_15(11, block, e, a, b, c, d, &mut array);
        self.t_0_15(12, block, d, e, a, b, c, &mut array);
        self.t_0_15(13, block, c, d, e, a, b, &mut array);
        self.t_0_15(14, block, b, c, d, e, a, &mut array);
        self.t_0_15(15, block, a, b, c, d, e, &mut array);

        /* Round 1 - tail. Input from 512-bit mixing array */
        self.t_16_19(16, &mut array, e, a, b, c, d);
        self.t_16_19(17, &mut array, d, e, a, b, c);
        self.t_16_19(18, &mut array, c, d, e, a, b);
        self.t_16_19(19, &mut array, b, c, d, e, a);

        /* Round 2 */
        self.t_20_39(20, &mut array, a, b, c, d, e);
        self.t_20_39(21, &mut array, e, a, b, c, d);
        self.t_20_39(22, &mut array, d, e, a, b, c);
        self.t_20_39(23, &mut array, c, d, e, a, b);
        self.t_20_39(24, &mut array, b, c, d, e, a);
        self.t_20_39(25, &mut array, a, b, c, d, e);
        self.t_20_39(26, &mut array, e, a, b, c, d);
        self.t_20_39(27, &mut array, d, e, a, b, c);
        self.t_20_39(28, &mut array, c, d, e, a, b);
        self.t_20_39(29, &mut array, b, c, d, e, a);
        self.t_20_39(30, &mut array, a, b, c, d, e);
        self.t_20_39(31, &mut array, e, a, b, c, d);
        self.t_20_39(32, &mut array, d, e, a, b, c);
        self.t_20_39(33, &mut array, c, d, e, a, b);
        self.t_20_39(34, &mut array, b, c, d, e, a);
        self.t_20_39(35, &mut array, a, b, c, d, e);
        self.t_20_39(36, &mut array, e, a, b, c, d);
        self.t_20_39(37, &mut array, d, e, a, b, c);
        self.t_20_39(38, &mut array, c, d, e, a, b);
        self.t_20_39(39, &mut array, b, c, d, e, a);

        /* Round 3 */
        self.t_40_59(40, &mut array, a, b, c, d, e);
        self.t_40_59(41, &mut array, e, a, b, c, d);
        self.t_40_59(42, &mut array, d, e, a, b, c);
        self.t_40_59(43, &mut array, c, d, e, a, b);
        self.t_40_59(44, &mut array, b, c, d, e, a);
        self.t_40_59(45, &mut array, a, b, c, d, e);
        self.t_40_59(46, &mut array, e, a, b, c, d);
        self.t_40_59(47, &mut array, d, e, a, b, c);
        self.t_40_59(48, &mut array, c, d, e, a, b);
        self.t_40_59(49, &mut array, b, c, d, e, a);
        self.t_40_59(50, &mut array, a, b, c, d, e);
        self.t_40_59(51, &mut array, e, a, b, c, d);
        self.t_40_59(52, &mut array, d, e, a, b, c);
        self.t_40_59(53, &mut array, c, d, e, a, b);
        self.t_40_59(54, &mut array, b, c, d, e, a);
        self.t_40_59(55, &mut array, a, b, c, d, e);
        self.t_40_59(56, &mut array, e, a, b, c, d);
        self.t_40_59(57, &mut array, d, e, a, b, c);
        self.t_40_59(58, &mut array, c, d, e, a, b);
        self.t_40_59(59, &mut array, b, c, d, e, a);

        /* Round 4 */
        self.t_60_79(60, &mut array, a, b, c, d, e);
        self.t_60_79(61, &mut array, e, a, b, c, d);
        self.t_60_79(62, &mut array, d, e, a, b, c);
        self.t_60_79(63, &mut array, c, d, e, a, b);
        self.t_60_79(64, &mut array, b, c, d, e, a);
        self.t_60_79(65, &mut array, a, b, c, d, e);
        self.t_60_79(66, &mut array, e, a, b, c, d);
        self.t_60_79(67, &mut array, d, e, a, b, c);
        self.t_60_79(68, &mut array, c, d, e, a, b);
        self.t_60_79(69, &mut array, b, c, d, e, a);
        self.t_60_79(70, &mut array, a, b, c, d, e);
        self.t_60_79(71, &mut array, e, a, b, c, d);
        self.t_60_79(72, &mut array, d, e, a, b, c);
        self.t_60_79(73, &mut array, c, d, e, a, b);
        self.t_60_79(74, &mut array, b, c, d, e, a);
        self.t_60_79(75, &mut array, a, b, c, d, e);
        self.t_60_79(76, &mut array, e, a, b, c, d);
        self.t_60_79(77, &mut array, d, e, a, b, c);
        self.t_60_79(78, &mut array, c, d, e, a, b);
        self.t_60_79(79, &mut array, b, c, d, e, a);

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
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

    fn update(&mut self, data_in: &[u8], len: usize) {
        let mut lenW = self.size & 63;

        self.size += len;

        if lenW > 0 {
            let mut left = 64 - lenW;
            if len < left {
                left = len;
            }
        }
    }

    fn finalize(&self) -> [u8; 20] {
        todo!()
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

trait ConsecutiveBitXor: BitXor<Output = Self> + Copy {}
trait AlternateXorWithAnd: ConsecutiveBitXor + BitAnd<Output = Self> {}
trait Test3: AlternateXorWithAnd + Add<Output = Self> {}

fn f_1<T>(b: &T, c: &T, d: &T) -> T
where
    T: AlternateXorWithAnd,
{
    *d ^ (*b & (*c ^ *d))
}

fn f_2<T>(b: &T, c: &T, d: &T) -> T
where
    T: ConsecutiveBitXor,
{
    *b ^ *c ^ *d
}

fn f_3<T>(b: &T, c: &T, d: &T) -> T
where
    T: Test3,
{
    (*b & *c) + (*d & (*b ^ *c))
}

fn swab32(val: &u32) -> u32 {
    ((*val & 0xff000000) >> 24)
        | ((*val & 0x00ff0000) >> 8)
        | ((*val & 0x0000ff00) << 8)
        | ((*val & 0x000000ff) << 24)
}
