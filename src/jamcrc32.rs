/// Wrapper around a [`crc32fast::Hasher`] that calculates a JAMCRC32
/// instead of a more standard ISO-HDLC CRC32.
///
/// Only the necessary subset of the `crc32fast::Hasher` interface is
/// implemented.
pub struct Jamcrc32Hasher {
    wrapped: crc32fast::Hasher,
}

impl Jamcrc32Hasher {
    /// Wrapper around [`crc32fast::Hasher::new_with_initial`].
    pub fn new_with_initial(init: u32) -> Self {
        Self {
            // Note the bitflip here
            wrapped: crc32fast::Hasher::new_with_initial(!init),
        }
    }

    /// Wrapper around [`crc32fast::Hasher::update`].
    pub fn update(&mut self, buf: &[u8]) {
        self.wrapped.update(buf);
    }

    /// Wrapper around [`crc32fast::Hasher::finalize`].
    pub fn finalize(self) -> u32 {
        // Note the bitflip here
        !self.wrapped.finalize()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn assert_jamcrc32(data: &[u8], init: u32, expected: u32) {
        let mut hasher = Jamcrc32Hasher::new_with_initial(init);
        hasher.update(data);
        assert_eq!(hasher.finalize(), expected);
    }

    #[test]
    fn test_jamcrc32() {
        assert_jamcrc32(b"123456789", 0, 0x2dfd2d88);
        assert_jamcrc32(b"123456789", 0xffff_ffff, 0x340bc6d9);
        assert_jamcrc32(b"123456789", 0x1234, 0x60be8a00);
    }
}
