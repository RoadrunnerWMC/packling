use std::{
    ffi::OsStr,
    fs::File,
    io::{BufReader, BufWriter, Write, Cursor},
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


/// Read and unpack a .pak to a specified output folder.
pub fn unpack(
    input_file: &Path,
    output_folder: &Path,
    key: KeyRef,
    force: bool,
    order_file: Option<&str>,
    verbosity: Verbosity,
) -> anyhow::Result<()> {
    if output_folder.is_dir() {
        if force {
            std::fs::remove_dir_all(output_folder).ok();
        } else {
            bail!("output directory exists (use -f to force)");
        }
    }

    let mut reader = BufReader::new(File::open(input_file)?);

    let mut order_file_writer = if let Some(order_file) = order_file {
        let f = File::options()
            .read(true)
            .write(true)
            .truncate(true)
            .create(true)
            .open(order_file);
        Some(BufWriter::new(f?))
    } else {
        None
    };

    let header = PakHeader::read(&mut reader)?;

    if header.version != FILE_VERSION {
        bail!("unknown PAK version: {}", header.version);
    }

    if verbosity == Verbosity::Verbose {
        let ts = time::OffsetDateTime::from_unix_timestamp(header.timestamp)?;
        let format = time::format_description::parse(TIME_FORMAT)?;
        println!("PAK file created {} ({})", ts.format(&format)?, header.timestamp);
    }

    let mut assets_list_data = decrypt_from_reader(
        &mut reader,
        ASSETS_LIST_NAME,
        u64::try_from(PAK_HEADER_SIZE)?,
        header.assets_list_size_compressed.try_into()?,
        key,
    )?;

    if header.assets_list_size_compressed != header.assets_list_size_decompressed {
        assets_list_data = lz4_flex::block::decompress(
            &assets_list_data,
            header.assets_list_size_decompressed.try_into().unwrap(),
        )?.into();
    }

    let assets = PakAssets::read(&mut Cursor::new(assets_list_data))?;

    for asset in assets.contents {
        let name_str = std::str::from_utf8(&asset.name)?;
        if verbosity == Verbosity::Verbose {
            println!("{name_str}");
        }
        if let Some(ref mut w) = order_file_writer {
            writeln!(w, "{name_str}")?;
        }

        let abs_offset = u32::try_from(PAK_HEADER_SIZE)? + header.assets_list_size_compressed + asset.offset;
        let mut asset_data = decrypt_from_reader(
            &mut reader,
            &asset.name,
            abs_offset.into(),
            asset.size_compressed.try_into()?,
            key,
        )?;

        if asset.size_compressed != asset.size_decompressed {
            asset_data = lz4_flex::block::decompress(
                &asset_data,
                asset.size_decompressed.try_into().unwrap(),
            )?.into();
        }

        let asset_path = Path::new(OsStr::new(name_str));

        // https://stackoverflow.com/a/69515135
        if asset_path.components().any(|c| c == std::path::Component::ParentDir) {
            bail!("directory traversal: {asset_path:?}");
        }

        let output_path = output_folder.join(asset_path);
        let output_subfolder = output_path.parent();
        let Some(output_subfolder) = output_subfolder else {
            bail!("output file {output_path:?} has no clear parent");
        };

        std::fs::create_dir_all(output_subfolder)?;
        std::fs::write(output_path, asset_data)?;
    }

    if let Some(ref mut w) = order_file_writer {
        w.flush()?;
    }

    Ok(())
}
