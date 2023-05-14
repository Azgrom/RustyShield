pub trait BigEndianBytes {
    type BigEndianBytesArray: AsRef<[u8]>;

    fn to_be_bytes(&self) -> Self::BigEndianBytesArray;
}
