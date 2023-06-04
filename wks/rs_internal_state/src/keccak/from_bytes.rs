pub(crate) trait FromBytes<T> {
    fn from_bytes(bytes: &[u8]) -> Self;
}
