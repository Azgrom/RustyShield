use core::hash::Hasher;
use hash_ctx_lib::HasherContext;
use crate::Shake128Hasher;

const MSG: &[u8; 43] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn test() {
    let mut shake128hasher = Shake128Hasher::<32>::default();

    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);
    shake128hasher.write(MSG);


    assert_eq!(shake128hasher.finish(), 0)
}

#[test]
fn test2() {
    let mut shake128hasher = Shake128Hasher::<32>::default();

    shake128hasher.write(MSG);

    let context = HasherContext::finish(&mut shake128hasher);
    assert_eq!(context, [0u8; 32]);
}
