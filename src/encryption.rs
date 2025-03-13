use std::io::{Read, Seek, SeekFrom};

use crate::key::KeyRef;


/// Size in bytes of encryption/decryption chunks. Each chunk uses a
/// different XXTEA key.
const XXTEA_CHUNK_SIZE: usize = 0x2000;


/// Generate an XXTEA key using the PAK file key generation algorithm.
///
/// - `name`: a string (usually the name of the file)
/// - `length`: the full length of the data blob
/// - `chunk_offset`: the offset of the 0x2000-byte chunk of encrypted
///   data (each chunk is encrypted with a different key)
fn generate_key(name: &[u8], length: u32, chunk_offset: u32, fixed_key: KeyRef) -> Box<[u8]> {
    let mut key = Box::new(*fixed_key);

    let mask = length ^ chunk_offset ^ djb2::Djb2a::hash_bytes(name).as_u32();

    #[allow(clippy::cast_possible_truncation)]
    for i in 0..4 {
        key[i * 4] &= mask as u8;
        key[i * 4 + 1] &= (mask >> 8) as u8;
        key[i * 4 + 2] &= (mask >> 16) as u8;
        key[i * 4 + 3] &= (mask >> 24) as u8;
    }

    key
}


/// Encrypt a blob of PAK data in-place.
///
/// `name` is a string that's used as part of key generation.
pub fn encrypt(name: &[u8], key: KeyRef, data: &mut [u8]) {
    let data_len = data.len();

    for chunk_start in (0..data.len()).step_by(XXTEA_CHUNK_SIZE) {
        // Note: if the data length isn't a multiple of 4, the last few
        // bytes are just unencrypted
        let chunk_size = (data.len() - chunk_start).min(XXTEA_CHUNK_SIZE) & !3;

        if chunk_size <= 4 {
            // "< 4" would make more sense, but in practice, 4-byte
            // files are unencrypted (see
            // punch_out_prd/art/wwiseaudio/FE_Music.txt and
            // Transitions_FrontEnd.txt), so this is correct
            return;
        }

        let chunk = &mut data[chunk_start..(chunk_start + chunk_size)];

        #[allow(clippy::cast_possible_truncation)]
        let key = generate_key(name, data_len as u32, chunk_start as u32, key);

        xxtea_nostd::encrypt(&key, chunk);
    }
}


/// Decrypt a blob of PAK data in-place.
///
/// `name` is a string that's used as part of key generation.
pub fn decrypt(name: &[u8], key: KeyRef, data: &mut [u8]) {
    let data_len = data.len();

    for chunk_start in (0..data.len()).step_by(XXTEA_CHUNK_SIZE) {
        // Note: if the data length isn't a multiple of 4, the last few
        // bytes are just unencrypted
        let chunk_size = (data.len() - chunk_start).min(XXTEA_CHUNK_SIZE) & !3;

        if chunk_size <= 4 {
            // "< 4" would make more sense, but in practice, 4-byte
            // files are unencrypted (see
            // punch_out_prd/art/wwiseaudio/FE_Music.txt and
            // Transitions_FrontEnd.txt), so this is correct
            return;
        }

        let chunk = &mut data[chunk_start..(chunk_start + chunk_size)];

        #[allow(clippy::cast_possible_truncation)]
        let key = generate_key(name, data_len as u32, chunk_start as u32, key);

        xxtea_nostd::decrypt(&key, chunk);
    }
}


/// Read a blob of encrypted data from a reader, and decrypt it.
///
/// `name` is a string that's used as part of key generation.
pub fn decrypt_from_reader<R: Read + Seek>(
    reader: &mut R,
    name: &[u8],
    offset: u64,
    size: usize,
    key: KeyRef,
) -> anyhow::Result<Box<[u8]>> {
    reader.seek(SeekFrom::Start(offset))?;

    let mut data = vec![0; size];
    reader.read_exact(&mut data)?;
    decrypt(name, key, &mut data);

    Ok(data.into_boxed_slice())
}


#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 16] = [
        0xa6, 0x42, 0xb2, 0x7a,
        0xe1, 0xda, 0x9e, 0x12,
        0xce, 0x0c, 0x61, 0x35,
        0xd7, 0x5c, 0xed, 0x68,
    ];

    fn assert_encrypt(name: &[u8], input: &[u8], output: &[u8]) {
        let mut data = Vec::from(input);
        encrypt(name, &TEST_KEY, &mut data);
        assert_eq!(&data, output);
    }

    #[test]
    fn test_encrypt() {
        assert_encrypt(b"test", b"",            &[]);
        assert_encrypt(b"test", b"1",           &[b'1']);
        assert_encrypt(b"test", b"12",          &[b'1', b'2']);
        assert_encrypt(b"test", b"123",         &[b'1', b'2', b'3']);
        assert_encrypt(b"test", b"1234",        &[b'1', b'2', b'3', b'4']);
        assert_encrypt(b"test", b"12345",       &[b'1', b'2', b'3', b'4', b'5']);
        assert_encrypt(b"test", b"123456",      &[b'1', b'2', b'3', b'4', b'5', b'6']);
        assert_encrypt(b"test", b"1234567",     &[b'1', b'2', b'3', b'4', b'5', b'6', b'7']);
        assert_encrypt(b"test", b"12345678",    &[0xf3, 0x67, 0xaf, 0x91, 0x81, 0x6b, 0xc8, 0x98]);
        assert_encrypt(b"test", b"123456789",   &[0xec, 0x81, 0xbd, 0xda, 0x95, 0xe9, 0xc2, 0xd5, b'9']);
        assert_encrypt(b"test", b"1234567890",  &[0x5a, 0x96, 0x80, 0x7a, 0x30, 0xfe, 0xf3, 0x19, b'9', b'0']);
        assert_encrypt(b"test", b"12345678901", &[0x75, 0xda, 0xf4, 0x22, 0xc7, 0xbf, 0x01, 0x81, b'9', b'0', b'1']);
    }

    fn assert_decrypt(name: &[u8], input: &[u8], output: &[u8]) {
        let mut data = Vec::from(input);
        decrypt(name, &TEST_KEY, &mut data);
        assert_eq!(&data, output);
    }

    #[test]
    fn test_decrypt() {
        assert_decrypt(b"test", &[],                                                                 b"");
        assert_decrypt(b"test", &[b'1'],                                                             b"1");
        assert_decrypt(b"test", &[b'1', b'2'],                                                       b"12");
        assert_decrypt(b"test", &[b'1', b'2', b'3'],                                                 b"123");
        assert_decrypt(b"test", &[b'1', b'2', b'3', b'4'],                                           b"1234");
        assert_decrypt(b"test", &[b'1', b'2', b'3', b'4', b'5'],                                     b"12345");
        assert_decrypt(b"test", &[b'1', b'2', b'3', b'4', b'5', b'6'],                               b"123456");
        assert_decrypt(b"test", &[b'1', b'2', b'3', b'4', b'5', b'6', b'7'],                         b"1234567");
        assert_decrypt(b"test", &[0xf3, 0x67, 0xaf, 0x91, 0x81, 0x6b, 0xc8, 0x98],                   b"12345678");
        assert_decrypt(b"test", &[0xec, 0x81, 0xbd, 0xda, 0x95, 0xe9, 0xc2, 0xd5, b'9'],             b"123456789");
        assert_decrypt(b"test", &[0x5a, 0x96, 0x80, 0x7a, 0x30, 0xfe, 0xf3, 0x19, b'9', b'0'],       b"1234567890");
        assert_decrypt(b"test", &[0x75, 0xda, 0xf4, 0x22, 0xc7, 0xbf, 0x01, 0x81, b'9', b'0', b'1'], b"12345678901");
    }
}
