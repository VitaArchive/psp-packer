use std::{ffi::FromBytesUntilNulError, fmt, io};

pub enum Error {
    AlreadyPacked,
    FromBytes {
        input_len: usize,
        expected_len: Option<usize>,
    },
    FileTooSmall,
    NotElf,
    NotPrx,
    NoModuleInfo,
    KernelPbp,
    MixedPrivileges,
    NoSegments,
    BssNotFound,
    NotPbp,
    Io(io::Error),
    Alignment {
        align: usize,
        addr: usize,
    },
    FileTooBig,
    CStr(FromBytesUntilNulError),
}

impl Error {
    pub fn error_code(&self) -> i32 {
        match self {
            Error::Io(_) => 101,
            Error::AlreadyPacked => 102,
            Error::NotPrx => 103,
            Error::NotPbp => 104,
            Error::NotElf => 105,
            Error::NoModuleInfo => 106,
            Error::FileTooBig => 107,
            Error::FileTooSmall => 108,
            Error::KernelPbp => 109,
            Error::MixedPrivileges => 110,
            Error::NoSegments => 111,
            Error::BssNotFound => 112,
            Error::FromBytes { .. } => 113,
            Error::Alignment { .. } => 114,
            Error::CStr(_) => 115,
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<FromBytesUntilNulError> for Error {
    fn from(value: FromBytesUntilNulError) -> Self {
        Self::CStr(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyPacked => f.pad("file already packed"),
            Error::FromBytes { .. } => {
                write!(f, "the program had a internal type conversion error: {self:?}")
            },
            Error::FileTooSmall => f.pad("the file is smaller than expected"),
            Error::NotElf => f.pad("no elf found"),
            Error::NotPrx => f.pad("the program was expecting a PRX file"),
            Error::NotPbp => f.pad("the program was expecting a PBP file"),
            Error::NoModuleInfo => {
                f.pad("the elf part of the file do not have a module info section")
            },
            Error::KernelPbp => f.pad("a kernel PBP is not a valid PSP format"),
            Error::MixedPrivileges => {
                f.pad("the file has mixed privileges between the elf and module info data")
            },
            Error::NoSegments => f.pad("the elf part of the file has no segments"),
            Error::BssNotFound => f.pad("the elf part of the file do not have a `.bss` section"),
            Error::Io(error) => write!(f, "{error}"),
            Error::Alignment { .. } => {
                write!(f, "the program had a internal type conversion error: {self:?}")
            },
            Error::FileTooBig => f.pad("the file is bigger than expected for a PSP file"),
            Error::CStr(e) => write!(f, "the program had a internal type conversion error: {e}"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyPacked => write!(f, "AlreadyPacked"),
            Self::FromBytes {
                input_len,
                expected_len,
            } => f
                .debug_struct("FromBytes")
                .field("input_len", input_len)
                .field("expected_len", expected_len)
                .finish(),
            Self::FileTooSmall => write!(f, "FileTooSmall"),
            Self::FileTooBig => write!(f, "FileTooBig"),
            Self::NotElf => write!(f, "NotElf"),
            Self::NotPrx => write!(f, "NotPrx"),
            Self::NoModuleInfo => write!(f, "NoModuleInfo"),
            Self::KernelPbp => write!(f, "KernelPbp"),
            Self::MixedPrivileges => write!(f, "MixedPrivileges"),
            Self::NoSegments => write!(f, "NoSegments"),
            Self::BssNotFound => write!(f, "BssNotFound"),
            Self::NotPbp => write!(f, "NotPbp"),
            Self::Io(arg0) => f.debug_tuple("Io").field(arg0).finish(),
            Self::Alignment { align, addr } => f
                .debug_struct("Alignment")
                .field("align", align)
                .field("addr", &format_args!("{addr:#08X}"))
                .finish(),
            Self::CStr(e) => f.debug_tuple("CStr").field(e).finish(),
        }
    }
}
