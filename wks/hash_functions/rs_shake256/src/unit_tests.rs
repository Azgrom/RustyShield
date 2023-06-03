extern crate alloc;

use crate::Shake256State;
use alloc::format;
use core::hash::{BuildHasher, Hasher};
use rs_hasher_ctx::HasherContext;

#[test]
fn assert_empty_string_hash_correctness() {
    let shake256state = Shake256State::<64>::default();
    let mut shake256hasher = shake256state.build_hasher();

    shake256hasher.write(b"");

    let output = HasherContext::finish(&mut shake256hasher);

    assert_eq!(format!("{output:02x}"), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
}
