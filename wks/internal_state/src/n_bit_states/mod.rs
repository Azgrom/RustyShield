pub(crate) mod sha160bits_state;
pub(crate) mod sha256bits_state;
pub(crate) mod sha512bits_state;

pub const LOWER_HEX_ERR: &str = "Error trying to format lower hex string";
pub const UPPER_HEX_ERR: &str = "Error trying to format upper hex string";

#[macro_export]
macro_rules! define_sha_state {
    ($TState:tt, $THasher:tt, Sha160BitsState) => {
        #[derive(Clone, Debug)]
        pub struct $TState(pub(crate) Sha160BitsState);

        use core::ops::AddAssign;
        impl AddAssign for $TState {
            fn add_assign(&mut self, rhs: Self) {
                self.0 += rhs.0
            }
        }

        use core::hash::BuildHasher;
        impl BuildHasher for $TState {
            type Hasher = $THasher;

            fn build_hasher(&self) -> Self::Hasher {
                use internal_hasher::BlockHasher;
                $THasher {
                    size: u64::MIN,
                    state: self.clone(),
                    padding: [0u8; $THasher::U8_PAD_SIZE as usize],
                }
            }
        }

        impl Default for $TState {
            fn default() -> Self {
                Self::from(HX)
            }
        }

        impl From<[u32; 5]> for $TState {
            fn from(v: [u32; 5]) -> Self {
                Self(Sha160BitsState::from(v))
            }
        }

        use internal_hasher::{GenericStateHasher, HasherWords};
        impl GenericStateHasher<u32> for $TState {
            fn block_00_15(&mut self, w: &HasherWords<u32>) {
                self.0.block_00_15(w)
            }

            fn block_16_31(&mut self, w: &mut HasherWords<u32>) {
                self.0.block_16_31(w)
            }

            fn block_32_47(&mut self, w: &mut HasherWords<u32>) {
                self.0.block_32_47(w)
            }

            fn block_48_63(&mut self, w: &mut HasherWords<u32>) {
                self.0.block_48_63(w)
            }

            fn block_64_79(&mut self, w: &mut HasherWords<u32>) {
                self.0.block_64_79(w)
            }
        }

        use core::hash::{Hash, Hasher};
        impl Hash for $TState {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }
    };

    ($TState:tt, $THasher:tt, Sha256BitsState) => {
        #[derive(Clone, Debug)]
        pub struct $TState(pub(crate) Sha256BitsState);

        use core::ops::AddAssign;
        impl AddAssign for $TState {
            fn add_assign(&mut self, rhs: Self) {
                self.0 += rhs.0
            }
        }

        use core::hash::BuildHasher;
        impl BuildHasher for $TState {
            type Hasher = $THasher;

            fn build_hasher(&self) -> Self::Hasher {
                use internal_hasher::BlockHasher;
                $THasher {
                    size: u64::MIN,
                    state: self.clone(),
                    padding: [0u8; $THasher::U8_PAD_SIZE as usize],
                }
            }
        }

        impl Default for $TState {
            fn default() -> Self {
                Self::from(HX)
            }
        }

        impl From<[u32; 8]> for $TState {
            fn from(v: [u32; 8]) -> Self {
                Self(Sha256BitsState::from(v))
            }
        }

        use internal_hasher::{GenericStateHasher, HasherWords};
        impl GenericStateHasher<u32> for $TState {
            fn block_00_15(&mut self, w: &HasherWords<u32>) {
                self.0.block_00_15(w)
            }

            fn block_16_31(&mut self, w: &mut HasherWords<u32>) {
                self.0.block_16_31(w)
            }

            fn block_32_47(&mut self, w: &mut HasherWords<u32>) {
                self.0.block_32_47(w)
            }

            fn block_48_63(&mut self, w: &mut HasherWords<u32>) {
                self.0.block_48_63(w)
            }

            fn block_64_79(&mut self, w: &mut HasherWords<u32>) {
                self.0.block_64_79(w)
            }
        }

        use core::hash::{Hash, Hasher};
        impl Hash for $TState {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }
    };

    ($TState:tt, $THasher:tt, Sha512BitsState) => {
        #[derive(Clone, Debug)]
        pub struct $TState(pub(crate) Sha512BitsState);

        use core::ops::AddAssign;
        impl AddAssign for $TState {
            fn add_assign(&mut self, rhs: Self) {
                self.0 += rhs.0
            }
        }

        use core::hash::BuildHasher;
        impl BuildHasher for $TState {
            type Hasher = $THasher;

            fn build_hasher(&self) -> Self::Hasher {
                use internal_hasher::BlockHasher;
                $THasher {
                    size: u128::MIN,
                    state: self.clone(),
                    padding: [0u8; $THasher::U8_PAD_SIZE as usize],
                }
            }
        }

        impl Default for $TState {
            fn default() -> Self {
                Self::from(HX)
            }
        }

        impl From<[u64; 8]> for $TState {
            fn from(v: [u64; 8]) -> Self {
                Self(Sha512BitsState::from(v))
            }
        }

        use internal_hasher::{GenericStateHasher, HasherWords};
        impl GenericStateHasher<u64> for $TState {
            fn block_00_15(&mut self, w: &HasherWords<u64>) {
                self.0.block_00_15(w)
            }

            fn block_16_31(&mut self, w: &mut HasherWords<u64>) {
                self.0.block_16_31(w)
            }

            fn block_32_47(&mut self, w: &mut HasherWords<u64>) {
                self.0.block_32_47(w)
            }

            fn block_48_63(&mut self, w: &mut HasherWords<u64>) {
                self.0.block_48_63(w)
            }

            fn block_64_79(&mut self, w: &mut HasherWords<u64>) {
                self.0.block_64_79(w)
            }
        }

        use core::hash::{Hash, Hasher};
        impl Hash for $TState {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }
    };
}
