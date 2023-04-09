use crate::{BytePad, U32Pad};

#[test]
fn test1(){
    assert_eq!(U32Pad::last_index(&U32Pad::default()), 63);
}

#[test]
fn test2(){
    assert_eq!(U32Pad::offset(&U32Pad::default()), 55);
}
