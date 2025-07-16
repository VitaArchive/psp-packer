use crate::{
    error::Error,
    utils::{AsBytes, TryFromBytes},
};

const ELF_MAGIC: u32 = 0x464C457F;
const ELF_TYPE_PRX: u16 = 0xFFA0;

#[repr(C)]
#[derive(Clone)]
#[cfg_attr(feature = "dev", derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct Elf32Ehdr {
    pub e_magic: u32,
    pub e_class: u8,
    pub e_data: u8,
    pub e_idver: u8,
    pub pad: [u8; 9],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl TryFromBytes for Elf32Ehdr {
    fn validate(src: &Self) -> Result<&Self, Error> {
        if src.e_magic != ELF_MAGIC {
            return Err(Error::NotElf);
        }
        Ok(src)
    }
}

impl AsBytes for Elf32Ehdr {}

impl Elf32Ehdr {
    #[inline]
    pub fn is_prx(&self) -> bool {
        self.e_type == ELF_TYPE_PRX
    }
}

#[repr(C)]
#[derive(Clone)]
#[cfg_attr(feature = "dev", derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct Elf32Phdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

impl TryFromBytes for Elf32Phdr {
    fn validate(src: &Self) -> Result<&Self, Error> {
        Ok(src)
    }
}

impl AsBytes for Elf32Phdr {}


#[repr(C)]
#[derive(Clone)]
#[cfg_attr(feature = "dev", derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct Elf32Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub sh_offset: u32,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

impl TryFromBytes for Elf32Shdr {
    fn validate(src: &Self) -> Result<&Self, Error> {
        Ok(src)
    }
}

impl AsBytes for Elf32Shdr {}
