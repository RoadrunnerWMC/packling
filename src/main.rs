use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use clap::{ValueEnum, Parser};

use crate::{
    key::KeyRef,
    shared::{Verbosity, check_is_encrypted},
};

mod encryption;
mod flow_just_decrypt;
mod flow_pack;
mod flow_unpack;
mod jamcrc32;
mod key;
mod shared;


/// Available formats to output to.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default, ValueEnum)]
#[clap(rename_all = "kebab_case")]
enum OutputFormat {
    /// A normal, encrypted .pak file.
    EncryptedPakFile,
    /// A .pak file without encryption applied, but everything else
    /// (including checksum values) exactly as it would be otherwise.
    /// Lingcod can't load paks in this form, but it's useful for
    /// debugging.
    DecryptedPakFile,
    /// An extracted folder.
    Folder,
    /// Just print info about the file to stdout, don't actually convert
    /// anything.
    PrintInfo,
    /// Guess what you probably want to do (pak file -> folder; folder
    /// -> encrypted pak file).
    #[default]
    Default,
}


#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// key.bin or lib<game>.so file containing the XXTEA encryption key
    key_file: PathBuf,

    /// Input .pak file (for unpacking) or folder (for packing)
    input: PathBuf,

    /// Output .pak file (for packing) or folder (for unpacking)
    output: Option<PathBuf>,

    /// Output format
    #[arg(long, default_value="default")]
    output_format: OutputFormat,

    /// Suppress output
    #[arg(short, long)]
    quiet: bool,

    /// Overwrite output file/folder if it already exists
    #[arg(short, long)]
    force: bool,

    /// Compress the .pak header (WARNING: may nearly double the encoding time)
    #[arg(long)]
    compress_header: bool,

    /// Compress files in the .pak
    #[arg(long)]
    compress_files: bool,

    /// Optional text file listing file paths in the .pak, in the order they should be encoded.
    ///
    /// This file will be created/updated if unpacking a .pak, or read if creating a .pak.
    ///
    /// Files not in the list are placed at the end, and nonexistent files in the list are ignored.
    #[arg(long)]
    order_file: Option<String>,

    /// Timestamp to put in the created .pak file header.
    ///
    /// Unix timestamp values (decimal, or hexadecimal with leading "0x") and the ISO 8601-style "2000-01-01T01:01:01" format are both supported.
    ///
    /// If unspecified, the current local system time will be used.
    #[arg(long)]
    timestamp: Option<String>,
}


/// Append "_out" to the filename pointed to by a `Path`.
fn add_out_suffix_to_filename(file: &Path) -> PathBuf {
    let mut name = file.file_name().unwrap_or(OsStr::new("")).to_owned();
    name.push("_out");
    file.with_file_name(&name)
}


/// Select a reasonable output folder name, if the user didn't specify
/// one.
fn pick_default_output_folder(input_file: &Path) -> PathBuf {
    let ext = input_file.extension();
    let Some(ext) = ext else {
        return add_out_suffix_to_filename(input_file);
    };
    if ext.is_empty() {
        return add_out_suffix_to_filename(input_file);
    };
    input_file.with_extension("")
}


/// Select a reasonable output .pak file name, if the user didn't
/// specify one.
fn pick_default_output_file(input_folder: &Path) -> PathBuf {
    if input_folder.file_name().is_none() {
        input_folder.join("out.pak")
    } else {
        input_folder.with_extension("pak")
    }
}


fn parse_timestamp_arg(string: Option<&str>) -> anyhow::Result<i64> {
    Ok(match string {
        Some(ts) => {
            if ts.chars().all(|c| c.is_ascii_digit() || c == '-') {
                ts.parse::<i64>()?
            } else if let Some(stripped) = ts.strip_prefix("0x") {
                i64::from_str_radix(stripped, 16)?
            } else if let Some(stripped) = ts.strip_prefix("-0x") {
                -i64::from_str_radix(stripped, 16)?
            } else {
                let format = time::format_description::parse(crate::shared::TIME_FORMAT)?;
                time::PrimitiveDateTime::parse(ts, &format)?
                    .assume_utc()
                    .unix_timestamp()
            }
        },
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .try_into()?,
    })
}


fn handle_unpack_file_to_folder(cli: Cli, key: KeyRef, verbosity: Verbosity) -> anyhow::Result<()> {
    if cli.compress_header {
        bail!("--compress-header is only allowed when packing");
    }
    if cli.compress_files {
        bail!("--compress-files is only allowed when packing");
    }
    if cli.timestamp.is_some() {
        bail!("--timestamp is only allowed when packing");
    }

    let output = match cli.output {
        Some(p) => p,
        None => pick_default_output_folder(&cli.input),
    };

    crate::flow_unpack::unpack(&cli.input, &output, key, cli.force, cli.order_file.as_deref(), verbosity)
}


fn handle_pack_folder_to_file(cli: Cli, key: KeyRef, verbosity: Verbosity) -> anyhow::Result<()> {
    let output = match cli.output {
        Some(p) => p,
        None => pick_default_output_file(&cli.input),
    };

    let timestamp = parse_timestamp_arg(cli.timestamp.as_deref())?;

    let should_decrypt = matches!(cli.output_format, OutputFormat::DecryptedPakFile);

    // Skipping encryption during packing makes it impossible to
    // calculate the correct whole-file checksum, so instead, we pack
    // the whole thing encrypted, and then decrypt it afterward

    crate::flow_pack::pack(&cli.input, &output, key, timestamp, cli.force, cli.compress_header, cli.compress_files, cli.order_file.as_deref(), verbosity)?;

    if should_decrypt {
        crate::flow_just_decrypt::decrypt(
            &output,
            &output,
            key,
            true,
            verbosity,
        )?;
    }

    Ok(())
}


fn handle_repack_file_to_file(cli: Cli, key: KeyRef, verbosity: Verbosity) -> anyhow::Result<()> {
    if cli.compress_header {
        bail!("--compress-header is not allowed when encrypting or decrypting a file to another file");
    }
    if cli.compress_files {
        bail!("--compress-files is not allowed when encrypting or decrypting a file to another file");
    }
    if cli.timestamp.is_some() {
        bail!("--timestamp is not allowed when encrypting or decrypting a file to another file");
    }
    if cli.order_file.is_some() {
        bail!("--order-file is not allowed when encrypting or decrypting a file to another file");
    }

    let output = match cli.output {
        Some(p) => p,
        None => cli.input.clone(),  // shrug
    };

    let input_encryption = check_is_encrypted(&cli.input)?;
    let output_encryption = match cli.output_format {
        OutputFormat::EncryptedPakFile => true,
        OutputFormat::DecryptedPakFile => false,
        OutputFormat::Default => !input_encryption,
        _ => bail!("internal error: trying to repack into unsupported format {:?}", cli.output_format),
    };

    if input_encryption == output_encryption {
        if input_encryption {
            bail!("this pak file is already encrypted");
        } else {
            bail!("this pak file is already decrypted");
        }
    }

    if output_encryption {
        todo!()
    } else {
        crate::flow_just_decrypt::decrypt(
            &cli.input,
            &output,
            key,
            cli.force,
            verbosity,
        )?;
    }

    Ok(())
}


fn handle_print_file_info(_cli: Cli, _key: KeyRef, _verbosity: Verbosity) -> anyhow::Result<()> {
    todo!()
}


/// Main entrypoint function
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let verbosity = if cli.quiet {
        Verbosity::NotVerbose
    } else {
        Verbosity::Verbose
    };

    let key = crate::key::get_key(&cli.key_file)?;

    if cli.input.is_file() {
        match cli.output_format {
            OutputFormat::Folder
            | OutputFormat::Default => handle_unpack_file_to_folder(cli, &key, verbosity)?,
            OutputFormat::EncryptedPakFile
            | OutputFormat::DecryptedPakFile => handle_repack_file_to_file(cli, &key, verbosity)?,
            OutputFormat::PrintInfo => handle_print_file_info(cli, &key, verbosity)?,
        }
    } else if cli.input.is_dir() {
        match cli.output_format {
            OutputFormat::EncryptedPakFile
            | OutputFormat::DecryptedPakFile
            | OutputFormat::Default => handle_pack_folder_to_file(cli, &key, verbosity)?,
            OutputFormat::Folder => bail!("converting an extracted folder to an extracted folder doesn't make sense"),
            OutputFormat::PrintInfo => bail!("printing info about an extracted folder doesn't make sense"),
        }
    } else {
        bail!("input file/folder not found");
    }

    Ok(())
}
