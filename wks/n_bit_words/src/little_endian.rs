pub trait FromLittleEndianBytes {
    fn from_le_bytes(bytes: &[u8]) -> Self;
}
