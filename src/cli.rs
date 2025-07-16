use std::path::PathBuf;

use clap::{
    builder::styling::{AnsiColor, Styles},
    crate_authors, crate_description, crate_name, crate_version, value_parser, Arg, ArgAction,
    Command,
};


pub(crate) fn create_app() -> Command {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default())
        .usage(AnsiColor::Green.on_default())
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::Green.on_default());

    Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .styles(styles)
        .arg(
            Arg::new("FILE")
                .help("The file to be packed.")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("tags")
                .long("tags")
                .short('s')
                .help("The tags to use")
                .num_args(2)
                .value_names(["TAG", "OE_TAG"])
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .short('n')
                .help("Don't actually write the compressed file")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Verbose output to stderr")
                .long_help(
                    "Verbose output to stderr\n\nCurrently, it mostly output warning messages and \
                     some compression information",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Specify the output file")
                .long_help(
                    "Specify the output file\n\nIf this option is not specified, the program will \
                     overwrite the passed <FILE>",
                )
                .value_name("OUT_FILE")
                .value_parser(value_parser!(PathBuf)),
        )
}
