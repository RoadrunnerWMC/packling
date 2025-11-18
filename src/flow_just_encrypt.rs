use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write, Cursor, Seek, SeekFrom},
    path::Path,
};

use anyhow::bail;
use binrw::{BinRead, BinWrite};

use crate::{
    encryption::encrypt as encrypt_blob,
    key::KeyRef,
    shared::{
        ASSETS_LIST_NAME,
        FILE_VERSION,
        PAK_HEADER_SIZE,
        PAK_ASSET_PLAINTEXT_CRC32_OFFSET_RELATIVE_TO_END,
        PAK_ASSET_CIPHERTEXT_CRC32_OFFSET_RELATIVE_TO_END,
        TIME_FORMAT,
        PakHeader,
        PakAsset,
        Verbosity,
        fix_header_crc32,
    },
};


/// Encrypt the contents of a decrypted .pak file (and update its
/// checksums), without extracting it to the filesystem.
pub fn encrypt(
    input_file: &Path,
    output_file: &Path,
    key: KeyRef,
    force: bool,
    verbosity: Verbosity,
) -> anyhow::Result<()> {

    // If we're not encrypting in-place...
    if !same_file::is_same_file(input_file, output_file).unwrap_or(false) {
        // ...make a copy of the input file at the output file path
        if !force && output_file.is_file() {
            bail!("output file exists (use -f to force)");
        }
        std::fs::copy(input_file, output_file)?;
    }

    // From now on, we encrypt output_file in-place.
    #[allow(unused_variables)]
    let input_file = ();

    // Open the output file
    let f = File::options()
        .read(true)
        .write(true)
        .open(output_file);

    let mut reader = BufReader::new(f?);

    // Read header and assets list
    let header = PakHeader::read(&mut reader)?;

    if header.version != FILE_VERSION {
        bail!("unknown PAK version: {}", header.version);
    }

    if header.assets_list_size_compressed != header.assets_list_size_decompressed {
        // This is tricky because we'd have to decompress and recompress
        // the assets list in addition to encrypting it, and then deal
        // with the fact that all the files will inevitably move around
        // as a result of the compressed size changing.
        //
        // That's also probably not what the user even wants, so should
        // we even support this at all...?
        todo!();
    }

    if verbosity == Verbosity::Verbose {
        let ts = time::OffsetDateTime::from_unix_timestamp(header.timestamp)?;
        let format = time::format_description::parse(TIME_FORMAT)?;
        println!("PAK file created {} ({})", ts.format(&format)?, header.timestamp);
    }

    reader.seek(SeekFrom::Start(u64::try_from(PAK_HEADER_SIZE)?))?;

    let mut assets_list_data = vec![0; header.assets_list_size_compressed.try_into()?];
    reader.read_exact(&mut assets_list_data)?;

    let assets_count = u32::read_le(&mut Cursor::new(&assets_list_data))?;

    // Encrypt all the files, fix up their checksums, and write them
    // back
    let mut assets_list_writer_holder = Some(BufWriter::new(Cursor::new(assets_list_data)));
    let mut file_writer_holder = Some(BufWriter::new(reader.into_inner()));
    let mut assets_list_offset = u64::try_from(std::mem::size_of::<u32>())?;

    for _ in 0..assets_count {
        let assets_list_writer = assets_list_writer_holder
            .expect("assets_list_writer_holder should be Some here");
        let file_writer = file_writer_holder
            .expect("file_writer_holder should be Some here");

        // Read PakAsset
        let mut assets_list_reader = BufReader::new(assets_list_writer.into_inner()?);

        assets_list_reader.seek(SeekFrom::Start(assets_list_offset))?;
        let asset = PakAsset::read(&mut assets_list_reader)?;
        assets_list_offset = assets_list_reader.stream_position()?;

        let name_str = std::str::from_utf8(&asset.name)?;
        if verbosity == Verbosity::Verbose {
            println!("{name_str}");
        }

        let abs_offset = u32::try_from(PAK_HEADER_SIZE)? + header.assets_list_size_compressed + asset.offset;

        // Read file data
        let mut file_reader = BufReader::new(file_writer.into_inner()?);
        file_reader.seek(SeekFrom::Start(abs_offset.into()))?;

        let mut asset_data = vec![0; asset.size_compressed.try_into()?];
        file_reader.read_exact(&mut asset_data)?;

        // Encrypt and write back file data, while recomputing checksums
        let mut file_writer = BufWriter::new(file_reader.into_inner());
        file_writer.seek(SeekFrom::Start(abs_offset.into()))?;

        let plaintext_crc32 = crc32fast::hash(&asset_data);
        encrypt_blob(&asset.name, key, &mut asset_data);
        file_writer.write_all(&asset_data)?;
        let ciphertext_crc32 = crc32fast::hash(&asset_data);

        // Write the updated checksums back to the assets list
        let mut assets_list_writer = BufWriter::new(assets_list_reader.into_inner());

        let offset_1 = assets_list_offset - u64::try_from(PAK_ASSET_PLAINTEXT_CRC32_OFFSET_RELATIVE_TO_END)?;
        assets_list_writer.seek(SeekFrom::Start(offset_1))?;
        plaintext_crc32.write_le(&mut assets_list_writer)?;

        let offset_2 = assets_list_offset - u64::try_from(PAK_ASSET_CIPHERTEXT_CRC32_OFFSET_RELATIVE_TO_END)?;
        assets_list_writer.seek(SeekFrom::Start(offset_2))?;
        ciphertext_crc32.write_le(&mut assets_list_writer)?;

        file_writer_holder = Some(file_writer);
        assets_list_writer_holder = Some(assets_list_writer);
    }

    let mut writer = file_writer_holder
        .expect("writer_holder should be Some here");
    let assets_list_writer = assets_list_writer_holder
        .expect("assets_list_writer_holder should be Some here");

    // Encrypt the assets list and write it back
    let mut assets_list_data = assets_list_writer.into_inner()?.into_inner();
    encrypt_blob(ASSETS_LIST_NAME, key, &mut assets_list_data);

    writer.seek(SeekFrom::Start(PAK_HEADER_SIZE.try_into()?))?;
    writer.write_all(&assets_list_data)?;

    // Finally, recompute and write the header CRC32
    let file = writer.into_inner()?;
    let total_file_size = file.metadata().unwrap().len();
    fix_header_crc32(file, total_file_size)
}
