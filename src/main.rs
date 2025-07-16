use std::{
    fs::{self},
    path::PathBuf,
};

use crate::{error::Error, psp::UnkPspExecutable};

mod cli;
mod elf;
mod error;
mod psp;
mod utils;

fn main() {
    let res = exec();

    if let Err(e) = res {
        eprintln!("psp-packer: {e}");
        std::process::exit(e.error_code());
    }
}

fn exec() -> Result<(), Error> {
    let cmd = cli::create_app();
    let matches = cmd.get_matches();

    // Ok to unwrap as it is required.
    let file_name = matches.get_one::<PathBuf>("FILE").unwrap();
    let output_file = matches.get_one::<PathBuf>("output");

    let dry_run = matches.get_flag("dry-run");
    let verbose = matches.get_flag("verbose");

    let tags = matches
        .get_many::<u32>("tags")
        .and_then(|mut tags| tags.next().copied().zip(tags.next().copied()));

    let file = UnkPspExecutable::from_path(file_name)?;
    let og_file_size = file.size();
    let compressed = match tags {
        Some((psp_tag, oe_tag)) => file.compress_with_tags(psp_tag, oe_tag)?,
        None => file.compress()?,
    };

    if dry_run {
        if verbose {
            eprintln!("psp-packer: WARNING: not writing to file due to dry run");
        }
    } else if let Some(output_file) = output_file {
        fs::write(output_file, compressed.as_bytes())?;
    } else {
        if verbose {
            eprintln!(
                "psp-packer: WARNING: `output` option not used, overwriting `{}`",
                file_name.display()
            );
        }
        fs::write(file_name, compressed.as_bytes())?;
    }

    if verbose {
        eprintln!("psp-packer: The file is a {}", compressed.kind());
        eprintln!(
            "psp-packer: Original file size: {:.2} KiB ({og_file_size} B)",
            og_file_size as f64 / 1024.0
        );
        eprintln!(
            "psp-packer: Compressed file size: {:.2} KiB ({} B)",
            compressed.size() as f64 / 1024.0,
            compressed.size()
        );
    }

    Ok(())
}
