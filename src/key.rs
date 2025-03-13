use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use anyhow::bail;


const KEY_OFFSETS: [u64; 6] = [
    0,          // key.bin
    0x10_56a0,  // libnsmb.so
    0x11_2b10,  // libpunch_out.so
    0x10_3380,  // libtwipri.so (v1 and v2)
    0x12_4da0,  // libsmg.so
    0x12_0da0,  // libdkcr.so
];

const KEY_SIZE: usize = 16;

pub type OwnedKey = Box<[u8; KEY_SIZE]>;
pub type KeyRef<'a> = &'a[u8; KEY_SIZE];

const KEY_CRC32: u32 = 0xaa13_14bf;


/// Try to retrieve the XXTEA encryption key from the indicated file.
pub fn get_key(file: &Path) -> anyhow::Result<OwnedKey> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("XXTEA key file \"{}\" is not a file", file.display());
    }

    let mut reader = BufReader::new(File::open(file)?);

    let mut possible_key: [u8; KEY_SIZE] = [0; KEY_SIZE];
    for offset in KEY_OFFSETS {
        reader.seek(SeekFrom::Start(offset))?;
        if reader.read(&mut possible_key)? == KEY_SIZE {
            if crc32fast::hash(&possible_key) == KEY_CRC32 {
                return Ok(Box::new(possible_key));
            }
        }
    }

    bail!("unable to find XXTEA key in \"{}\"", file.display());
}
