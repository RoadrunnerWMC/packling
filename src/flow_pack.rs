use std::{
    collections::HashSet,
    fs::File,
    io::{BufReader, BufRead, BufWriter, Read, Write, Cursor, Seek, SeekFrom, ErrorKind},
    path::Path,
};

use anyhow::bail;
use binrw::{BinWrite, BinWriterExt};

use crate::{
    encryption::encrypt,
    jamcrc32::Jamcrc32Hasher,
    key::KeyRef,
    shared::{
        ASSETS_LIST_NAME,
        FILE_VERSION,
        PAK_HEADER_SIZE,
        PAK_CRC32_OFFSET,
        PAK_CRC32_START_OFFSET,
        Verbosity,
        PakHeader,
        PakAsset,
        PakAssets,
    },
};


// Just using the same value as `BufReader` from the Rust stdlib
const CRC32_DATA_BUFFER_SIZE: usize = 8 * 1024;


/// Create a .pak file with the contents of the specified folder.
pub fn pack(
    input_folder: &Path,
    output_file: &Path,
    key: KeyRef,
    timestamp: i64,
    force: bool,
    compress_header: bool,
    compress_files: bool,
    order_file: Option<&str>,
    verbosity: Verbosity,
) -> anyhow::Result<()> {

    // First, gather file entries in the correct order (first following
    // the order file if provided, then everything else in sorted order)

    let mut file_paths_vec = Vec::new();
    let mut file_paths_set = HashSet::new();

    if let Some(order_file) = order_file {
        let order_file_reader = BufReader::new(File::open(order_file)?);
        for path_within_pak in order_file_reader.lines().map_while(Result::ok) {
            let path_on_host = input_folder.join(&path_within_pak);

            if path_on_host.is_file() {
                file_paths_vec.push(path_on_host.clone());
                file_paths_set.insert(path_on_host);
            }
            // ignore any lines referring to nonexistent files
        }
    }

    for entry in walkdir::WalkDir::new(input_folder).sort_by_file_name() {
        let entry = entry?;

        if !entry.file_type().is_file() {
            continue;
        }

        let path_on_host = entry.path();

        if file_paths_set.contains(path_on_host) {
            continue;
        }

        file_paths_vec.push(path_on_host.to_path_buf());
        // no need to update the set anymore
    }

    // With this, we can calculate the total size of the assets list and
    // header
    let mut assets_list_bytes_len = 4;
    for path_on_host in &file_paths_vec {
        let path_within_pak = path_on_host.strip_prefix(input_folder)?;
        assets_list_bytes_len += 0x20 + path_within_pak.as_os_str().len();
    }

    let total_header_size = PAK_HEADER_SIZE + assets_list_bytes_len;

    // Open the output file
    let f = File::options()
        .read(true)
        .write(true)
        .truncate(true)
        .create(force)
        .create_new(!force)
        .open(output_file);
    if let Err(ref e) = f {
        if e.kind() == ErrorKind::AlreadyExists {
            bail!("output file exists (use -f to force)");
        }
    }

    let mut writer = BufWriter::new(f?);

    // Write some zeroes to reserve space for the header
    writer.write_all(&vec![0_u8; total_header_size])?;

    // Now write all the files (encrypted), and prepare the PakAssets

    let mut assets_list = Vec::new();
    let mut assets_data_offset = 0;

    for path_on_host in file_paths_vec {
        let path_within_pak = path_on_host.strip_prefix(input_folder)?;

        // Need to build this string manually in case we're running on
        // a platform that doesn't use "/" separators (e.g. Windows)
        let capacity = path_within_pak.as_os_str().as_encoded_bytes().len() + 1;
        let mut asset_name_bytes = Vec::with_capacity(capacity);
        for component in path_within_pak.iter() {
            asset_name_bytes.extend_from_slice(component.as_encoded_bytes());
            asset_name_bytes.push(b'/');
        }
        asset_name_bytes.pop();

        if verbosity == Verbosity::Verbose {
            println!("{}", String::from_utf8_lossy(&asset_name_bytes));
        }

        let mut asset_data = std::fs::read(&path_on_host)?;

        let decompressed_size = asset_data.len();

        if compress_files {
            let compressed_asset_data = lz4_flex::block::compress(&asset_data);
            // only use the compressed version if it's actually smaller
            if compressed_asset_data.len() < asset_data.len() {
                asset_data = compressed_asset_data;
            }
        }
        let compressed_size = asset_data.len();

        let plaintext_crc32 = crc32fast::hash(&asset_data);
        encrypt(&asset_name_bytes, key, &mut asset_data);
        writer.write_all(&asset_data)?;
        let ciphertext_crc32 = crc32fast::hash(&asset_data);

        assets_list.push(PakAsset {
            name: asset_name_bytes.to_vec(),
            size_decompressed: u32::try_from(decompressed_size)?,
            size_compressed: u32::try_from(compressed_size)?,
            offset: u32::try_from(assets_data_offset)?,
            plaintext_crc32,
            ciphertext_crc32,
        });

        assets_data_offset += asset_data.len();
    }

    let total_file_size = writer.stream_position()?;

    // Now go back and fill in the PakAssets list (encrypted)...
    writer.seek(SeekFrom::Start(PAK_HEADER_SIZE.try_into()?))?;

    let mut header_buf_cursor = Cursor::new(Vec::new());
    (PakAssets {contents: assets_list}).write(&mut header_buf_cursor)?;
    let mut header_buf = header_buf_cursor.into_inner();

    // TODO: support compressing the file table
    // (contains offsets, but they're relative to the end of the compressed table data,
    // so there's no weird cyclic dependency issue)
    if compress_header {
        todo!()
    }

    let plaintext_crc32 = crc32fast::hash(&header_buf);
    encrypt(ASSETS_LIST_NAME, key, &mut header_buf);
    writer.write_all(&header_buf)?;
    let ciphertext_crc32 = crc32fast::hash(&header_buf);

    // ...and the unencrypted header (without the CRC32 yet)
    let header = PakHeader {
        version: FILE_VERSION,
        crc32: 0,
        unk0c: 1,
        timestamp,
        assets_list_size_decompressed: u32::try_from(assets_list_bytes_len)?,
        assets_list_size_compressed: u32::try_from(assets_list_bytes_len)?,
        plaintext_crc32,
        ciphertext_crc32,
    };

    writer.seek(SeekFrom::Start(0))?;
    header.write(&mut writer)?;

    // Finally, fix the header CRC32
    fix_header_crc32(writer.into_inner()?, total_file_size)
}


fn fix_header_crc32(file: File, total_file_size: u64) -> anyhow::Result<()> {
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
