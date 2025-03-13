use std::{
    fs::File,
    io::{BufReader, BufWriter, Write, Cursor, Seek, SeekFrom},
    path::Path,
};

use anyhow::bail;
use binrw::BinRead;

use crate::{
    encryption::decrypt_from_reader,
    key::KeyRef,
    shared::{
        ASSETS_LIST_NAME,
        FILE_VERSION,
        PAK_HEADER_SIZE,
        TIME_FORMAT,
        PakHeader,
        PakAssets,
        Verbosity,
    },
};


/// Decrypt the contents of a .pak file, without extracting it to the
/// filesystem.
pub fn decrypt(
    input_file: &Path,
    output_file: &Path,
    key: KeyRef,
    force: bool,
    verbosity: Verbosity,
) -> anyhow::Result<()> {

    // If we're not decrypting in-place...
    if input_file.canonicalize()? != output_file.canonicalize()? {
        // ...make a copy of the input file at the output file path
        if !force && output_file.is_file() {
            bail!("output file exists (use -f to force)");
        }
        std::fs::copy(input_file, output_file)?;
    }

    // From now on, we decrypt output_file in-place.
    #[allow(unused_variables)]
    let input_file = ();

    // Open the output file
    let f = File::options()
        .read(true)
        .write(true)
        .open(output_file);

    let mut reader = BufReader::new(f?);

    // Read header and assets list, and decrypt the latter
    let header = PakHeader::read(&mut reader)?;

    if header.version != FILE_VERSION {
        bail!("unknown PAK version: {}", header.version);
    }

    if verbosity == Verbosity::Verbose {
        let ts = time::OffsetDateTime::from_unix_timestamp(header.timestamp)?;
        let format = time::format_description::parse(TIME_FORMAT)?;
        println!("PAK file created {} ({})", ts.format(&format)?, header.timestamp);
    }

    let assets_list_data = decrypt_from_reader(
        &mut reader,
        ASSETS_LIST_NAME,
        u64::try_from(PAK_HEADER_SIZE)?,
        header.assets_list_size_compressed.try_into()?,
        key,
    )?;

    // Write it back
    let mut writer = BufWriter::new(reader.into_inner());
    writer.seek(SeekFrom::Start(PAK_HEADER_SIZE.try_into()?))?;
    writer.write_all(&assets_list_data)?;

    // Parse it
    let assets = PakAssets::read(&mut Cursor::new(assets_list_data))?;

    // Decrypt all the files and write them back, too
    let mut writer_holder = Some(writer);
    for asset in assets.contents {
        let name_str = std::str::from_utf8(&asset.name)?;
        if verbosity == Verbosity::Verbose {
            println!("{name_str}");
        }

        let abs_offset = u32::try_from(PAK_HEADER_SIZE)? + header.assets_list_size_compressed + asset.offset;

        let writer = writer_holder.expect("writer_holder should be Some here");
        let mut reader = BufReader::new(writer.into_inner()?);

        let asset_data = decrypt_from_reader(
            &mut reader,
            &asset.name,
            abs_offset.into(),
            asset.size_compressed.try_into()?,
            key,
        )?;

        let mut writer = BufWriter::new(reader.into_inner());

        writer.seek(SeekFrom::Start(abs_offset.into()))?;
        writer.write_all(&asset_data)?;

        writer_holder = Some(writer);
    }

    Ok(())
}
