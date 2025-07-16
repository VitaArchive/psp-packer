use std::{
    ffi::{c_void, CStr},
    fmt, fs,
    io::{Cursor, Read, Write},
    path::Path,
};

use bitflag_attr::bitflag;
use flate2::{Compression, GzBuilder};
use rand::Rng;

#[cfg(feature = "dev")]
use bstr::ByteSlice;

use crate::{
    elf::{Elf32Ehdr, Elf32Phdr, Elf32Shdr},
    error::Error,
    utils::{self, AsBytes, TryFromBytes},
};

const PSP_HEADER_MAGIC: u32 = 0x5053507E;
const PBP_HEADER_MAGIC: u32 = 0x50425000;

const ISIZE_MAX: usize = 9_223_372_036_854_775_807;

/// A PSP file of a unknown format.
#[repr(transparent)]
#[cfg_attr(feature = "dev", derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct UnkPspExecutable(Box<[u8]>);

impl UnkPspExecutable {
    fn new(buf: Box<[u8]>) -> Self {
        Self(buf)
    }

    pub fn from_path(path: &Path) -> Result<Self, Error> {
        let file = fs::read(path)?;
        if file.len() >= ISIZE_MAX {
            return Err(Error::FileTooBig);
        }

        Ok(Self::new(file.into_boxed_slice()))
    }

    pub fn compress(self) -> Result<CompPspExecutable, Error> {
        self.compress_impl(None, None)
    }

    pub fn compress_with_tags(self, psp_tag: u32, oe_tag: u32) -> Result<CompPspExecutable, Error> {
        self.compress_impl(Some(psp_tag), Some(oe_tag))
    }

    /// Compress implementation
    fn compress_impl(
        mut self, psp_tag: Option<u32>, oe_tag: Option<u32>,
    ) -> Result<CompPspExecutable, Error> {
        let mut exec_size = self.size();
        let mut exec_kind = ExecutableKind::UserPrx;
        let mut exec_offset = 0;
        let exec = self.as_mut_bytes();

        let mut exec_cursor = Cursor::new(&exec);
        let mut file_magic = [0u8; 4];
        exec_cursor.read_exact(&mut file_magic)?;
        let file_magic = u32::from_le_bytes(file_magic);

        if file_magic == PSP_HEADER_MAGIC {
            return Err(Error::AlreadyPacked);
        }

        if file_magic == PBP_HEADER_MAGIC {
            let pbp = PbpHeader::ref_from_bytes(exec)?;
            exec_kind = ExecutableKind::Pbp;
            exec_size = (pbp.psar_offset - pbp.prx_offset) as usize;
            exec_offset = pbp.prx_offset as usize;
        }

        let elf_range = exec_offset..exec_size;
        let elf_header = {
            let elf_slice = exec.get(elf_range.clone()).ok_or(Error::FileTooSmall)?;
            Elf32Ehdr::from_bytes(elf_slice)?
        };

        // if exec_kind.is_pbp() && elf_header.is_prx() {
        //     // `exec_kind` is set to PBP only if a PBP header is found
        //     // In this case, the ELF header should never be marked as being a PRX
        //     return Err(Error::NotPbp);
        // }

        if exec_kind.is_prx() && !elf_header.is_prx() {
            // At this point, being a PRX is the only option, but if the header ELF header is not
            // marked with PRX magic value, then this is not a PSP PRX ELF file.
            return Err(Error::NotPrx);
        }

        let mod_info_phdr = find_module_info_phdr(exec, exec_offset)?;
        let mod_info_shdr = find_segment(exec, exec_offset, c".rodata.sceModuleInfo")?;

        let is_kernel_module =
            mod_info_phdr.as_ref().is_some_and(|phdr| (phdr.p_paddr & 0x80000000) != 0);

        if is_kernel_module && exec_kind.is_pbp() {
            return Err(Error::KernelPbp);
        } else if is_kernel_module {
            exec_kind = ExecutableKind::KernelPrx;
        }

        let mod_info_off = match (mod_info_phdr, mod_info_shdr) {
            (Some(phdr), _) => phdr.p_paddr,
            (None, Some(shdr)) => shdr.sh_offset,
            // Should never happen as we already check for that case before
            (None, None) => return Err(Error::NoModuleInfo),
        };
        let mod_info_start = exec_offset + (mod_info_off & 0x7FFFFFFF) as usize;
        let mod_info_slice = exec.get(mod_info_start..).ok_or(Error::FileTooSmall)?;
        let mut mod_info = SceModuleInfo::from_bytes(mod_info_slice)?;


        if (is_kernel_module && !mod_info.mod_attr.contains(ModInfoAttribute::KernelMode))
            || (!is_kernel_module && mod_info.mod_attr.contains(ModInfoAttribute::KernelMode))
        {
            return Err(Error::MixedPrivileges);
        }

        let mut psp_header = PspHeader {
            attribute: mod_info.mod_attr,
            module_info_offset: mod_info_off,

            // set comp attribute to use gzip
            comp_attribute: 1,
            module_version_low: mod_info.mod_version_low,
            module_version_high: mod_info.mod_version_high,
            ..Default::default()
        };

        for (&info, psp) in mod_info.mod_name.iter().zip(psp_header.module_name.iter_mut()) {
            *psp = info;
        }

        psp_header.elf_size = exec_size as u32;
        psp_header.entry = elf_header.e_entry;

        psp_header.num_segments = match elf_header.e_phnum {
            0 => return Err(Error::NoSegments),
            x if x > 4 => return Err(Error::NoSegments),
            x => x as u8,
        };

        read_segments_bss_info(exec, exec_offset, &mut psp_header)?;

        psp_header.set_decript_mode(exec_kind.is_pbp());

        // Update mod_info for changes
        mod_info.mod_attr = psp_header.attribute;
        let mod_info_range = mod_info_start..mod_info_start + size_of::<SceModuleInfo>();
        let mod_info_slice = exec.get_mut(mod_info_range).ok_or(Error::FileTooSmall)?;
        mod_info_slice.copy_from_slice(mod_info.as_bytes());

        psp_header.tag = psp_tag.unwrap_or_else(|| default_psp_tag_handler(exec_kind));
        psp_header.oe_tag = oe_tag.unwrap_or_else(|| default_oe_tag_handler(exec_kind));

        // Fill key data with random data
        let mut rnd = utils::rand();
        rnd.fill(&mut psp_header.key_data0);
        rnd.fill(&mut psp_header.key_data1);
        rnd.fill(&mut psp_header.key_data3);

        let guess_size = utils::gzip_max_compressed_size(exec_size);
        let mut compressed_cursor =
            Cursor::new(Vec::with_capacity(guess_size + size_of::<PspHeader>()));

        // Skip the psp_header from the compressed buffer
        compressed_cursor.set_position(size_of_val(&psp_header) as u64);
        let elf_slice = exec.get(elf_range).ok_or(Error::FileTooSmall)?;
        let mut gzip = GzBuilder::new()
            .operating_system(0x0B)
            .write(&mut compressed_cursor, Compression::best());
        gzip.write_all(elf_slice)?;
        gzip.finish()?;

        // Update psp header
        let new_size = compressed_cursor.get_ref().len();
        psp_header.comp_size = (new_size - size_of::<PspHeader>()) as u32;
        psp_header.psp_size = new_size as u32;
        let exec_comp_size = new_size - size_of::<PspHeader>();

        // dbg!("FINAL_PSP_HEADER", &psp_header);

        // write psp header and set position back
        let last_pos = compressed_cursor.position();
        compressed_cursor.set_position(0);
        compressed_cursor.write_all(psp_header.as_bytes())?;
        compressed_cursor.set_position(last_pos);


        // if PBP we need to insert the PBP header/icons etc
        if exec_kind.is_pbp() {
            let pbp_header = exec.get(..exec_offset).ok_or(Error::FileTooSmall)?;
            let pbp_icon_start = exec_offset + exec_size;
            let pbp_icons = exec.get(pbp_icon_start..).ok_or(Error::FileTooSmall)?;

            compressed_cursor.write_all(pbp_icons)?;
            compressed_cursor.set_position(0);
            compressed_cursor.write_all(pbp_header)?;


            let compressed_pbp_slice = compressed_cursor.get_mut().as_mut_slice();
            let pbp = PbpHeader::mut_from_bytes(compressed_pbp_slice)?;
            pbp.psar_offset = (exec_offset + exec_comp_size) as u32;
        }


        Ok(CompPspExecutable::new(
            compressed_cursor.into_inner().into_boxed_slice(),
            exec_kind,
        ))
    }

    /// File size in bytes.
    pub fn size(&self) -> usize {
        self.0.len()
    }

    #[allow(unused, reason = "maybe use in the future (maybe as lib)")]
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

impl AsRef<[u8]> for UnkPspExecutable {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for UnkPspExecutable {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

/// A compressed PSP executable with known kind.
#[cfg_attr(feature = "dev", derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct CompPspExecutable {
    content: Box<[u8]>,
    kind: ExecutableKind,
}

impl CompPspExecutable {
    fn new(buf: Box<[u8]>, kind: ExecutableKind) -> Self {
        Self { content: buf, kind }
    }

    /// Returns the file size in bytes.
    pub fn size(&self) -> usize {
        self.content.len()
    }

    /// Returns the PSP executable kind.
    pub fn kind(&self) -> ExecutableKind {
        self.kind
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    #[allow(unused, reason = "maybe use in the future (maybe as lib)")]
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

impl AsRef<[u8]> for CompPspExecutable {
    fn as_ref(&self) -> &[u8] {
        self.content.as_ref()
    }
}

impl AsMut<[u8]> for CompPspExecutable {
    fn as_mut(&mut self) -> &mut [u8] {
        self.content.as_mut()
    }
}


#[repr(C)]
#[cfg_attr(feature = "dev", derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct PbpHeader {
    pub magic: u32,
    pub version: u32,
    pub sfo_offset: u32,
    pub icon0_offset: u32,
    pub icon1_offset: u32,
    pub pic0_offset: u32,
    pub pic1_offset: u32,
    pub snd0_offset: u32,
    pub prx_offset: u32,
    pub psar_offset: u32,
}

#[cfg(feature = "dev")]
impl fmt::Debug for PbpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PbpHeader")
            .field("magic", &format_args!("0x{:08X}", self.magic))
            .field("version", &format_args!("0x{:X}", self.version))
            .field("sfo_offset", &format_args!("0x{:08X}", self.sfo_offset))
            .field("icon0_offset", &format_args!("0x{:08X}", self.icon0_offset))
            .field("icon1_offset", &format_args!("0x{:08X}", self.icon1_offset))
            .field("pic0_offset", &format_args!("0x{:08X}", self.pic0_offset))
            .field("pic1_offset", &format_args!("0x{:08X}", self.pic1_offset))
            .field("snd0_offset", &format_args!("0x{:08X}", self.snd0_offset))
            .field("prx_offset", &format_args!("0x{:08X}", self.prx_offset))
            .field("psar_offset", &format_args!("0x{:08X}", self.psar_offset))
            .finish()
    }
}

impl TryFromBytes for PbpHeader {
    fn validate(src: &Self) -> Result<&Self, Error> {
        if src.magic != PBP_HEADER_MAGIC {
            return Err(Error::NotPbp);
        }
        Ok(src)
    }
}

impl AsBytes for PbpHeader {}

#[repr(C, align(4))]
#[cfg_attr(feature = "dev", derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct SceModuleInfo {
    pub mod_attr: ModInfoAttribute,
    pub mod_version_low: u8,
    pub mod_version_high: u8,
    pub mod_name: [u8; 27],
    pub terminal: u8,
    pub gp_value: *mut c_void,
    pub ent_top: *mut c_void,
    pub ent_end: *mut c_void,
    pub stub_top: *mut c_void,
    pub stub_end: *mut c_void,
}

#[cfg(feature = "dev")]
impl fmt::Debug for SceModuleInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SceModuleInfo")
            .field("mod_attr", &self.mod_attr)
            .field("mod_version_low", &self.mod_version_low)
            .field("mod_version_high", &self.mod_version_high)
            .field("mod_name", &self.mod_name.as_bstr())
            .field("terminal", &self.terminal)
            .field("gp_value", &self.gp_value)
            .field("ent_top", &self.ent_top)
            .field("ent_end", &self.ent_end)
            .field("stub_top", &self.stub_top)
            .field("stub_end", &self.stub_end)
            .finish()
    }
}

impl TryFromBytes for SceModuleInfo {
    fn validate(src: &Self) -> Result<&Self, Error> {
        Ok(src)
    }
}

impl AsBytes for SceModuleInfo {}

#[repr(C)]
#[cfg_attr(feature = "dev", derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct PspHeader {
    pub signature: u32,
    pub attribute: ModInfoAttribute,
    pub comp_attribute: u16,
    pub module_version_low: u8,
    pub module_version_high: u8,
    pub module_name: [u8; 28],
    pub version: u8,
    pub num_segments: u8,
    pub elf_size: u32,
    pub psp_size: u32,
    pub entry: u32,
    pub module_info_offset: u32,
    pub bss_size: u32,
    pub seg_align: [u16; 4],
    pub seg_addr: [u32; 4],
    pub seg_size: [u32; 4],
    pub reserved: [u32; 5],
    pub devkit_version: u32,
    pub decrypt_mode: DecryptMode,
    pub padding: u8,
    pub overlap_size: u16,
    pub key_data0: [u8; 0x30],
    pub comp_size: u32,
    pub _80: u32,
    pub reserved2: [u32; 2],
    pub key_data1: [u8; 0x10],
    pub tag: u32,
    pub scheck: [u8; 0x58],
    pub key_data2: u32,
    pub oe_tag: u32,
    pub key_data3: [u8; 0x1C],
}

#[cfg(feature = "dev")]
impl fmt::Debug for PspHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PspHeader")
            .field("signature", &format_args!("0x{:08X}", self.signature))
            .field("attribute", &self.attribute)
            .field("comp_attribute", &self.comp_attribute)
            .field("module_version_low", &self.module_version_low)
            .field("module_version_high", &self.module_version_high)
            .field("module_name", &self.module_name.as_bstr())
            .field("version", &self.version)
            .field("num_segments", &self.num_segments)
            .field("elf_size", &self.elf_size)
            .field("psp_size", &self.psp_size)
            .field("entry", &self.entry)
            .field("module_info_offset", &self.module_info_offset)
            .field("bss_size", &self.bss_size)
            .field("seg_align", &format_args!("{:?}", self.seg_align))
            .field("seg_addr", &format_args!("{:?}", self.seg_addr))
            .field("seg_size", &format_args!("{:?}", self.seg_size))
            .field("reserved", &format_args!("{:?}", self.reserved))
            .field("devkit_version", &format_args!("0x{:08X}", self.devkit_version))
            .field("decrypt_mode", &self.decrypt_mode)
            .field("padding", &self.padding)
            .field("overlap_size", &self.overlap_size)
            .field("key_data0", &format_args!("{:?}", self.key_data0))
            .field("comp_size", &self.comp_size)
            .field("_80", &format_args!("0x{:02X}", self._80))
            .field("reserved2", &format_args!("{:?}", self.reserved2))
            .field("key_data1", &format_args!("{:?}", self.key_data1))
            .field("tag", &format_args!("0x{:08X}", self.tag))
            .field("scheck", &format_args!("{:?}", self.scheck))
            .field("key_data2", &self.key_data2)
            .field("oe_tag", &format_args!("0x{:08X}", self.oe_tag))
            .field("key_data3", &format_args!("{:?}", self.key_data3))
            .finish()
    }
}

impl Default for PspHeader {
    fn default() -> Self {
        Self {
            signature: PSP_HEADER_MAGIC,
            attribute: Default::default(),
            comp_attribute: Default::default(),
            module_version_low: Default::default(),
            module_version_high: Default::default(),
            module_name: Default::default(),
            version: 1,
            num_segments: Default::default(),
            elf_size: Default::default(),
            psp_size: Default::default(),
            entry: Default::default(),
            module_info_offset: Default::default(),
            bss_size: Default::default(),
            seg_align: Default::default(),
            seg_addr: Default::default(),
            seg_size: Default::default(),
            reserved: Default::default(),
            devkit_version: Default::default(),
            decrypt_mode: Default::default(),
            padding: Default::default(),
            overlap_size: Default::default(),
            key_data0: [0; 0x30],
            comp_size: Default::default(),
            _80: 0x80,
            reserved2: Default::default(),
            key_data1: Default::default(),
            tag: Default::default(),
            scheck: [0; 0x58],
            key_data2: Default::default(),
            oe_tag: Default::default(),
            key_data3: Default::default(),
        }
    }
}

impl TryFromBytes for PspHeader {
    fn validate(src: &Self) -> Result<&Self, Error> {
        Ok(src)
    }
}

impl AsBytes for PspHeader {}


#[bitflag(u16)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModInfoAttribute {
    /// Kernel mode
    KernelMode = 0x1000,
    /// Boot mode
    BootMode = 0x2000,
    /// VSH/XMB API (updater)
    VshAPI = 0x0800,
    /// App API (comics, etc)
    AppAPI = 0x0600,
    /// USB and WLAN API (skype, etc)
    UsbWlanAPI = 0x0400,
    /// MS API
    MsAPI  = 0x0200,
}

#[repr(u8)]
#[cfg_attr(feature = "dev", derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash))]
#[derive(Clone, Copy, Default)]
pub enum DecryptMode {
    Kernel = 0x2,
    Vsh    = 0x3,
    #[default]
    Standard = 0x4,
    Updater = 0xC,
    App    = 0xE,
    UsbWlan = 0xA,
    Ms     = 0xD,
}

impl PspHeader {
    pub fn set_decript_mode(&mut self, is_pbp: bool) {
        if self.attribute.contains(ModInfoAttribute::KernelMode) {
            if self.attribute.contains(ModInfoAttribute::BootMode) {
                self.devkit_version = 0x06060110;
            } else {
                self.devkit_version = 0x05070110;
            }

            self.decrypt_mode = DecryptMode::Kernel;
        } else if is_pbp {
            if self.attribute.contains(ModInfoAttribute::VshAPI) {
                self.decrypt_mode = DecryptMode::Updater;
            } else if self.attribute.contains(ModInfoAttribute::AppAPI) {
                self.decrypt_mode = DecryptMode::App;
            } else if self.attribute.contains(ModInfoAttribute::UsbWlanAPI) {
                self.decrypt_mode = DecryptMode::UsbWlan;
            } else {
                self.attribute |= ModInfoAttribute::MsAPI;
                self.decrypt_mode = DecryptMode::Ms;
                self.devkit_version = 0x06020010;
            }
        } else {
            // Standalone user PRX
            if self.attribute.contains(ModInfoAttribute::VshAPI) {
                self.decrypt_mode = DecryptMode::Vsh;
            } else {
                self.devkit_version = 0x05070210;
                self.decrypt_mode = DecryptMode::Standard;
            }
        }
    }
}

#[repr(u8)]
#[cfg_attr(feature = "dev", derive(Debug, PartialOrd, Ord, Hash))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecutableKind {
    UserPrx,
    KernelPrx,
    Pbp,
}

impl ExecutableKind {
    pub fn is_prx(&self) -> bool {
        matches!(self, ExecutableKind::KernelPrx | ExecutableKind::UserPrx)
    }

    pub fn is_pbp(&self) -> bool {
        matches!(self, ExecutableKind::Pbp)
    }
}

impl fmt::Display for ExecutableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutableKind::UserPrx => f.pad("User PRX"),
            ExecutableKind::KernelPrx => f.pad("Kernel PRX"),
            ExecutableKind::Pbp => f.pad("PBP"),
        }
    }
}


fn default_psp_tag_handler(kind: ExecutableKind) -> u32 {
    match kind {
        ExecutableKind::UserPrx => 0x457B06F0,
        ExecutableKind::KernelPrx => 0xDADADAF0,
        ExecutableKind::Pbp => 0xADF305F0,
    }
}

fn default_oe_tag_handler(kind: ExecutableKind) -> u32 {
    match kind {
        ExecutableKind::UserPrx => 0x8555ABF2,
        ExecutableKind::KernelPrx => 0x55668D96,
        ExecutableKind::Pbp => 0x7316308C,
    }
}

fn find_module_info_phdr(exec: &[u8], elf_start: usize) -> Result<Option<Elf32Phdr>, Error> {
    let elf_slice = exec.get(elf_start..).ok_or(Error::FileTooSmall)?;
    let elf_header = Elf32Ehdr::from_bytes(elf_slice)?;
    let phdr_start_off = elf_start + elf_header.e_phoff as usize;
    let phnum = elf_header.e_phnum as usize;

    let phdr_slice = exec.get(phdr_start_off..).ok_or(Error::FileTooSmall)?;
    let phdrs = Elf32Phdr::from_bytes_with_elems(phdr_slice, phnum)?;

    for phdr in phdrs {
        if phdr.p_type == 1 && phdr.p_vaddr != phdr.p_paddr {
            // Found module info
            return Ok(Some(phdr.clone()));
        }
    }

    Ok(None)
}

fn read_segments_bss_info(
    exec: &[u8], elf_start: usize, psp_header: &mut PspHeader,
) -> Result<(), Error> {
    let elf_slice = exec.get(elf_start..).ok_or(Error::FileTooSmall)?;
    let elf_header = Elf32Ehdr::from_bytes(elf_slice)?;

    let phdr_start_off = elf_start + elf_header.e_phoff as usize;
    let phnum = psp_header.num_segments as usize;

    let phdr_slice = exec.get(phdr_start_off..).ok_or(Error::FileTooSmall)?;
    let phdrs = Elf32Phdr::from_bytes_with_elems(phdr_slice, phnum)?;

    for (i, phdr) in phdrs.iter().enumerate() {
        psp_header.seg_align[i] = phdr.p_align as u16;
        psp_header.seg_addr[i] = phdr.p_vaddr;
        psp_header.seg_size[i] = phdr.p_memsz;
    }

    let shdr_start_off = elf_start + elf_header.e_shoff as usize;
    let shnum = elf_header.e_shnum as usize;
    let shdr_slice = exec.get(shdr_start_off..).ok_or(Error::FileTooSmall)?;
    let shdrs = Elf32Shdr::from_bytes_with_elems(shdr_slice, shnum)?;

    let strtab_offset = elf_start + shdrs[elf_header.e_shstrndx as usize].sh_offset as usize;

    for shdr in shdrs {
        let name_start = strtab_offset + shdr.sh_name as usize;
        let name_end = name_start + 4;
        let name = exec.get(name_start..name_end).ok_or(Error::FileTooSmall)?;
        if name == b".bss" {
            psp_header.bss_size = shdr.sh_size;
            return Ok(());
        }
    }

    Err(Error::BssNotFound)
}

fn find_segment(
    exec: &[u8], elf_start: usize, seg_name: &CStr,
) -> Result<Option<Elf32Shdr>, Error> {
    let elf_slice = exec.get(elf_start..).ok_or(Error::FileTooSmall)?;
    let elf_header = Elf32Ehdr::from_bytes(elf_slice)?;

    let shdr_start_off = elf_start + elf_header.e_shoff as usize;
    let shnum = elf_header.e_shnum as usize;
    let shdr_slice = exec.get(shdr_start_off..).ok_or(Error::FileTooSmall)?;
    let shdrs = Elf32Shdr::from_bytes_with_elems(shdr_slice, shnum)?;

    let strtab_offset = elf_start + shdrs[elf_header.e_shstrndx as usize].sh_offset as usize;

    for shdr in shdrs {
        let name_start = strtab_offset + shdr.sh_name as usize;
        let name = exec.get(name_start..).ok_or(Error::BssNotFound)?;
        let name = CStr::from_bytes_until_nul(name)?;
        if name == seg_name {
            return Ok(Some(shdr));
        }
    }

    Ok(None)
}

impl UnkPspExecutable {}
