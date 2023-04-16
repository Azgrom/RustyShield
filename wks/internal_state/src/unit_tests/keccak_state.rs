use alloc::format;
use crate::{KeccakState, Chi, Iota, Pi, Rho, Theta, HEIGHT, WIDTH};

// Test constants, based on examples from the Keccak reference
const INITIAL_STATE: [[u64; WIDTH]; HEIGHT] = [
    [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B],
    [0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088],
    [0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089],
    [0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A],
    [0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008, 0x0000000000000001],
];
// Test constants, after theta step
const AFTER_THETA_STATE: [[u64; WIDTH]; HEIGHT] = [
    [0x800000008000811E, 0x800000008000019D, 0x0000000080000195, 0x000000000000011F, 0x8000000080000194],
    [0x0000000100010197, 0x8000000100018117, 0x800000018001819F, 0x000000018001011C, 0x000000018001011E],
    [0x0000000180018180, 0x0000000180010183, 0x0000000180018102, 0x8000000100010102, 0x8000000100018100],
    [0x800000018001009A, 0x800000018001009B, 0x8000000180018019, 0x0000000180010093, 0x8000000100018093],
    [0x8000000100000104, 0x8000000180000105, 0x0000000100008184, 0x800000010000018D, 0x0000000180008184],
];
// Test constants, after rho step
const AFTER_RHO_STATE: [[u64; WIDTH]; HEIGHT] = [
    [0x0000000000000001, 0x0000000040410000, 0x4540000000000040, 0x0080000000800080, 0x00000002022C0000],
    [0x0000000100000002, 0x0010001010300000, 0x0000000000020026, 0x0000000000008A00, 0x0000440000000000],
    [0x0000000400040048, 0x08000000A0000000, 0x000020002022C000, 0x0000000117000000, 0x3000000000001011],
    [0x00000000002000E0, 0x0008002800000000, 0x0000000404000000, 0x0400500000000000, 0x0008000000A80000],
    [0x0000020002020600, 0x1010100000000000, 0x0000020000000100, 0x2000000020002002, 0x0000100000000000],
];
// Test constants, after pi step
const AFTER_PI_STATE: [[u64; WIDTH]; HEIGHT] = [
    [0x0000000000000001, 0x8000000000008003, 0x0000000080000001, 0x8000000080008081, 0x0000000080008009],
    [0x8000000080008081, 0x8000000000008080, 0x000000008000000A, 0x0000000000008082, 0x8000000000008002],
    [0x000000008000808B, 0x800000000000808A, 0x8000000000000080, 0x8000000000008009, 0x0000000080000001],
    [0x000000000000800A, 0x000000000000008A, 0x8000000080008008, 0x800000000000008B, 0x8000000080008000],
    [0x0000000000000001, 0x8000000000008089, 0x000000000000808B, 0x800000008000000A, 0x0000000000000088],
];
// Test constants, after chi step
const AFTER_CHI_STATE: [[u64; WIDTH]; HEIGHT] = [
    [0x0000000000008009, 0x0000000000008088, 0x8000000080008008, 0x0000000080008001, 0x800000000000008A],
    [0x8000000080000003, 0x0000000080000081, 0x0000000000008009, 0x000000000000808A, 0x000000008000008A],
    [0x0000000000008089, 0x000000008000008A, 0x000000000000808A, 0x000000008000008B, 0x8000000000008088],
    [0x8000000000008003, 0x8000000000008000, 0x000000000000800A, 0x000000000000800A, 0x8000000080008080],
    [0x8000000000008081, 0x0000000080008081, 0x0000000080000000, 0x8000000080008082, 0x0000000000000001],
];
// Test constants, after first iota step
const AFTER_IOTA_STATE_ON_FIRST_CYCLE: [[u64; WIDTH]; HEIGHT] = [
    [0x80006000C000011F, 0xCA800060000026A0, 0x04000C02CC02032E, 0x000004060004147E, 0x0103000C000C0E00],
    [0x0824983022F00C00, 0x0020B18001012C00, 0x7800101830000063, 0x0200420005CEC000, 0x1E1009B800000019],
    [0x0018200060409000, 0xDA80000020402020, 0x0C020C00CA520000, 0x0010001E083E067E, 0x01838700000002C0],
    [0x8804980080008D1E, 0x000001E001411A80, 0x600000024000034D, 0x0200060205041200, 0x1F00000C000C0C01],
    [0x0838403022F01800, 0x1020B00020002020, 0x1802101836520000, 0x0010401809F2C000, 0x009086B0000000D8],
];
// Test constants, after second iota step
const AFTER_IOTA_STATE_ON_SECOND_CYCLE: [[u64; WIDTH]; HEIGHT] = [
    [0x58E0E790540C7917, 0x8F55D7BD337A1C03, 0xB7696EEA5C769C85, 0xEE3C82DAD7B5674E, 0x37016E4FF7432EEC],
    [0xF02818CF385C3379, 0xBAF58B4C5376DFE9, 0x81EE4C97D583D41F, 0xE84D0C548F560900, 0xF8D55CEFC5DF5DC7],
    [0x45365537BDEFEA86, 0xF1EDD137732E9A9D, 0xE5F62E35D5A1CD34, 0x2642312477BDDF82, 0x16CD5DDD40B49D54],
    [0x4A39D6A13E27D7FC, 0x9E70538B1DB5D2F7, 0xCBCD8B8B312F5CE3, 0x273D160D620C3A9B, 0x62D8B8C691712354],
    [0x7D7C5EE606C8CBC5, 0xC053D1197F501D6B, 0x0236C59979BA269F, 0x606F84119EBE9BCF, 0xE16F755FC087A787],
];

#[test]
fn assert_theta_correctness() {
    let mut state = KeccakState::from(INITIAL_STATE);
    state.theta();
    assert_eq!(state, KeccakState::from(AFTER_THETA_STATE));
}

#[test]
fn assert_rho_correctness() {
    let mut state = KeccakState::from(INITIAL_STATE);
    state.rho();
    let string = format!("{state:016X?}");
    assert_eq!(state, KeccakState::from(AFTER_RHO_STATE));
}

#[test]
fn assert_pi_correctness() {
    let mut state = KeccakState::from(INITIAL_STATE);
    state.pi();
    assert_eq!(state, KeccakState::from(AFTER_PI_STATE));
}

#[test]
fn assert_chi_correctness() {
    let mut state = KeccakState::from(INITIAL_STATE);
    state.chi();
    assert_eq!(state, KeccakState::from(AFTER_CHI_STATE));
}
