pub trait LittleEndianBytes {
    type OutputBytesArray: AsRef<[u8]>;
    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn to_le_bytes(&self) -> Self::OutputBytesArray;
}
