# PSP Packer

A command line tool to compress the PRX and PBP PlayStation Portable file formats.

## Features

 - **Multi-platform**: This tools can be compiled in all major platforms (Linux, macOS, Windows, BSDs)
 - Supports user PRX, kernel PRX
 - Command line interface (CLI) compatibility with Davee version of the tool

## To-do

 - [ ] Support PBP
    - A buggy implementation is done, you can try using it, but chances are it is going to generate a bad file
 - [ ] Signing (Maybe)
 - [ ] Decompress (Maybe)

## Installing

### From crates.io:
```sh
cargo install psp-packer
```

### From source:

1. Clone the repository
```sh
git clone https://github.com/GrayJack/psp-packer.git
cd psp-packer
```

2. Build the binary
```sh
cargo build --release --target-dir=target
```

3. Copy the binary to PSPDEV binary folder

UNIX/UNIX-like:
```sh
cp target/release/psp-packer $PSPDEV/bin/
```

Windows: Grab the `target\release\psp-packer.exe` and put in the PSPDEV `bin` folder.

## Licensing

This software is licensed under the [Mozilla Public License, v. 2.0](./LICENSE)
(MPL). If a copy of the MPL was not distributed with this file, you can obtain
one at http://mozilla.org/MPL/2.0/.