use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom},
    path::Path,
};

use binrw::{binrw, BinReaderExt, BinWriterExt};

use crate::jamcrc32::Jamcrc32Hasher;


/// The size in bytes of `PakHeader`.
pub const PAK_HEADER_SIZE: usize = 0x28;
/// The offset of the CRC32 value in `PakHeader`.
pub const PAK_CRC32_OFFSET: usize = 0x8;
/// The offset at which calculation of the CRC32 at 0x08 in `PakHeader`
/// begins.
pub const PAK_CRC32_START_OFFSET: usize = 0x14;
/// The value of the file header "version" field found in all publicly
/// available PAK files.
pub const FILE_VERSION: u32 = 103;
/// The absolute value of the offset of the plaintext-CRC32 value in
/// `PakAsset` relative to the end of the struct.
pub const PAK_ASSET_PLAINTEXT_CRC32_OFFSET_RELATIVE_TO_END: usize = 0x8;
/// The absolute value of the offset of the ciphertext-CRC32 value in
/// `PakAsset` relative to the end of the struct.
pub const PAK_ASSET_CIPHERTEXT_CRC32_OFFSET_RELATIVE_TO_END: usize = 0x4;
/// The name (for key-generation purposes) of the assets list blob.
pub const ASSETS_LIST_NAME: &[u8; 6] = b"header";

/// The initial seed used for djb2 hashes.
const DJB2_HASH_SEED: u32 = 0x1505;
/// The multiplier used in djb2 hashing.
const DJB2_MULTIPLIER: u32 = 33;

/// Time format used for displaying dates to the user and reading them
/// from the CLI. Similar to ISO 8601, but without any timezone info.
pub const TIME_FORMAT: &str = "[year]-[month]-[day]T[hour]:[minute]:[second]";


// Just using the same value as `BufReader` from the Rust stdlib
const CRC32_DATA_BUFFER_SIZE: usize = 8 * 1024;


/// Represents the user-selected verbosity level.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub enum Verbosity {
    #[default]
    NotVerbose,
    Verbose,
}


/// Sign-extend a `u64` containing a 56-bit signed integer to `i64`.
/// The uppermost 8 bits are ignored.
#[allow(clippy::cast_possible_wrap)]
const fn u56_to_i64(value: u64) -> i64 {
    if (value & 0x0080_0000_0000_0000) == 0 {
        // positive
        (value & 0x00ff_ffff_ffff_ffff) as i64
    } else {
        // negative
        (value | 0xff00_0000_0000_0000) as i64
    }
}


/// Represents the unencrypted PAK header, of length `PAK_HEADER_SIZE`.
#[binrw]
#[brw(little, magic = b"KCAP")]
pub struct PakHeader {
    /* 0x04 */ pub version: u32,
    /* 0x08 */ pub crc32: u32,
    /* 0x0c */ pub unk0c: u8,  // always 1? flag? changing it doesn't do anything
    /*      */ // Doing some shenanigans to get a 7-byte signed
    /*      */ // timestamp value. It might just be 4 bytes + 3 pad in
    /*      */ // reality, but even if so, it'd be a shame to let those
    /*      */ // 3 bytes go to waste when we could use them this way
    /*      */ // instead...
    /*      */ #[br(map = u56_to_i64)]
    /* 0x0d */ pub timestamp: i64,
    /*      */ #[brw(seek_before(SeekFrom::Current(-1)))]
    /* 0x14 */ pub assets_list_size_decompressed: u32,
    /* 0x18 */ pub assets_list_size_compressed: u32,

    /*      */ // Same as the last 12 bytes of `PakAsset`
    /*      */ // TODO: which size to use?
    /*      */ #[bw(calc = djb2a_hash(ASSETS_LIST_NAME) ^ assets_list_size_compressed)]
    /* 0x1c */ _field_1c: u32,
    /* 0x20 */ pub plaintext_crc32: u32,
    /* 0x24 */ pub ciphertext_crc32: u32,
}


/// Represents a length-prefixed list of `PakAsset`.
#[binrw]
#[brw(little)]
pub struct PakAssets {
    #[bw(try_calc(u32::try_from(contents.len())))]
    _count: u32,

    #[br(count = _count)]
    pub contents: Vec<PakAsset>,
}


/// Calculate the expected value of `PakAsset` field 0x0c.
fn calc_field_0x0c(name: &[u8], size: u32) -> u32 {
    // very weird
    if size >= 0xa00000 || name.ends_with(b".alf") {
        2
    } else {
        0
    }
}


/// Calculate the expected value of `PakAsset` field 0x10.
fn calc_field_0x10(name: &[u8], size_compressed: u32) -> u32 {
    if size_compressed == 0 {
        0
    } else {
        djb2a_hash(name) ^ size_compressed
    }
}


/// Represents a single entry from the encrypted assets-list blob near
/// the start of the PAK file.
#[binrw]
#[brw(little)]
pub struct PakAsset {
    #[bw(try_calc(u32::try_from(name.len())))]
    name_len: u32,
    #[br(count = name_len)]
    pub name: Vec<u8>,

    // (Offsets measured from the end of `name`)
    /* 0x00 */ pub size_decompressed: u32,
    /* 0x04 */ pub size_compressed: u32,
    /* 0x08 */ pub offset: u32,

    /*      */ // TODO: which size to use?
    /*      */ #[bw(calc = calc_field_0x0c(name, *size_compressed))]
    /* 0x0c */ _field_0c: u32,

    /*      */ #[bw(calc = calc_field_0x10(name, *size_compressed))]
    /* 0x10 */ _field_10: u32,
    /* 0x14 */ pub plaintext_crc32: u32,
    /* 0x18 */ pub ciphertext_crc32: u32,
}


/// Check if the PAK file at `path` appears to be encrypted, using a
/// simple heuristic.
pub fn check_is_encrypted(path: &Path) -> anyhow::Result<bool> {
    let mut reader = BufReader::new(File::open(path)?);
    reader.seek(SeekFrom::Start(PAK_HEADER_SIZE.try_into()?))?;
    let num_files: u32 = reader.read_le()?;
    Ok(num_files > 0x000f_ffff)
}


/// Recalculate the CRC32 of the provided encrypted PAK file, and write
/// it to the correct header field (0x08).
pub fn fix_header_crc32(file: File, total_file_size: u64) -> anyhow::Result<()> {
    let mut reader = BufReader::new(file);

    // Calculate the JAMCRC32 of the entire file starting at
    // PAK_CRC32_START_OFFSET

    reader.seek(SeekFrom::Start(PAK_CRC32_START_OFFSET.try_into()?))?;

    let mut data_buffer = vec![0; CRC32_DATA_BUFFER_SIZE];
    #[allow(clippy::cast_possible_truncation)]
    let mut hasher = Jamcrc32Hasher::new_with_initial(total_file_size as u32);
    loop {
        let amount_read = reader.read(&mut data_buffer)?;
        hasher.update(&data_buffer[..amount_read]);
        if amount_read < CRC32_DATA_BUFFER_SIZE {
            break;
        }
    }
    let crc = hasher.finalize();

    // Switch back to a BufWriter, and write that value to 0x08

    let mut writer = BufWriter::new(reader.into_inner());

    writer.seek(SeekFrom::Start(PAK_CRC32_OFFSET.try_into()?))?;
    writer.write_le(&crc)?;

    writer.flush()?;
    Ok(())
}


/// Calculate the djb2a hash of some data.
pub fn djb2a_hash(data: &[u8]) -> u32 {
    let mut hash = DJB2_HASH_SEED;

    for c in data {
        hash = hash.wrapping_mul(DJB2_MULTIPLIER) ^ u32::from(*c);
    }

    hash
}
