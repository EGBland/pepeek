use std::fmt::Display;

use bitflags::bitflags;

use super::traits::PEHeader;

/// The two possible flavours of PE optional header.
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum PEType {
    Pe32 = 0x10b,
    Pe32Plus = 0x20b,
}

/// Machine types that a PE can target.
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum MachineType {
    Unknown = 0x0,
    Alpha = 0x184,
    Alpha64 = 0x284,
    Am33 = 0x1d3,
    Amd64 = 0x8664,
    Arm = 0x1c0,
    Arm64 = 0xaa64,
    ArmNT = 0x1c4,
    Ebc = 0xebc,
    I386 = 0x14c,
    Ia64 = 0x200,
    LoongArch32 = 0x6232,
    LoongArch64 = 0x6264,
    M32R = 0x9041,
    Mips16 = 0x266,
    MipsFpu = 0x366,
    MipsFpu16 = 0x466,
    PowerPc = 0x1f0,
    PowerPcFp = 0x1f1,
    R4000 = 0x166,
    RiscV32 = 0x5032,
    RiscV64 = 0x5064,
    RiscV128 = 0x5128,
    Sh3 = 0x1a2,
    Sh3Dsp = 0x1a3,
    Sh4 = 0x1a6,
    Sh5 = 0x1a8,
    Thumb = 0x1c2,
    WceMipsV2 = 0x169,
}

/// Possible Windows subsystems that a PE can require.
#[repr(u16)]
#[derive(Debug)]
pub enum WindowsSubsystem {
    Unknown = 0,
    Native = 1,
    WindowsGui = 2,
    WindowsCui = 3,
    Os2Cui = 5,
    PosixCui = 7,
    NativeWindows = 8,
    WindowsCeGui = 9,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13,
    Xbox = 14,
    WindowsBootApplication = 16,
}

bitflags! {
    /// PE characteristic flags given in the COFF header.
    #[derive(Debug, Clone, Copy)]
    pub struct CoffCharacteristics: u16 {
        const RelocsStripped = 0x0001;
        const ExecutableImage = 0x0002;
        const LineNumsStripped = 0x0004;
        const LocalSymsStripped = 0x0008;
        const AggressiveWsTrim = 0x0010;
        const LargeAddressAware = 0x0020;
        const BytesReservedLo = 0x0080;
        const Machine32Bit = 0x0100;
        const DebugStripped = 0x0200;
        const RemovableRunFromSwap = 0x0400;
        const NetRunFromSwap = 0x0800;
        const System = 0x1000;
        const Dll = 0x2000;
        const UpSystemOnly = 0x4000;
        const BytesReversedHi = 0x8000;
    }
}

bitflags! {
    /// PE DLL characteristic flags given in the Windows optional header.
    #[derive(Debug, Clone, Copy)]
    pub struct DllCharacteristics: u16 {
        const HighEntropyVa = 0x0020;
        const DynamicBase = 0x0040;
        const ForceIntegrity = 0x0080;
        const NxCompat = 0x0100;
        const NoIsolation = 0x0200;
        const NoSeh = 0x0400;
        const NoBind = 0x0800;
        const AppContainer = 0x1000;
        const WdmDriver = 0x2000;
        const GuardCf = 0x4000;
        const TerminalServerAware = 0x8000;
    }
}

/// A COFF header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CoffHeader {
    /// Targeted machine architecture.
    pub target_machine: MachineType,
    /// Number of sections.
    pub number_of_sections: u16,
    /// The file creation time, as the low 32 bits of the number of seconds since 1st Jan 1970 (like C's `time_t`).
    pub time_date_stamp: u32,
    /// Offset of the COFF symbol table, or zero if it is absent.
    pub pointer_to_symbol_table: u32,
    /// Number of symbols in the COFF symbol table.
    pub number_of_symbols: u32,
    /// Size of the optional header.
    pub size_of_optional_header: u16,
    /// COFF characteristics.
    pub characteristics: CoffCharacteristics,
}

/// Standard optional header for the PE32 flavour.
#[repr(C)]
#[derive(Debug)]
pub struct OptionalHeaderStandardFieldsPe32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialised_data: u32,
    pub size_of_uninitialised_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
}

/// Standard optional header for the PE32+ flavour.
#[repr(C)]
#[derive(Debug)]
pub struct OptionalHeaderStandardFieldsPe32Plus {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialised_data: u32,
    pub size_of_uninitialised_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
}

/// Windows optional header for the PE32 flavour.
#[repr(C)]
#[derive(Debug)]
pub struct OptionalHeaderWindowsFieldsPe32 {
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: WindowsSubsystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// Windows optional header for the PE32+ flavour.
#[repr(C)]
#[derive(Debug)]
pub struct OptionalHeaderWindowsFieldsPe32Plus {
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: WindowsSubsystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// A header data directory.
#[repr(C)]
#[derive(Debug)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// A full optional header for the PE32 flavour.
#[repr(C)]
#[derive(Debug)]
pub struct OptionalHeaderPe32 {
    pub standard_fields: OptionalHeaderStandardFieldsPe32,
    pub windows_fields: OptionalHeaderWindowsFieldsPe32,
}

/// A full optional header for the PE32+ flavour.
#[repr(C)]
#[derive(Debug)]
pub struct OptionalHeaderPe32Plus {
    pub standard_fields: OptionalHeaderStandardFieldsPe32Plus,
    pub windows_fields: OptionalHeaderWindowsFieldsPe32Plus,
}

/// A full set of headers for the PE32 flavour.
pub struct HeadersPe32 {
    pub coff_header: CoffHeader,
    pub optional_headers: OptionalHeaderPe32,
    pub data_directories: Vec<DataDirectory>,
}

/// A full set of headers for the PE32+ flavour.
pub struct HeadersPe32Plus {
    pub coff_header: CoffHeader,
    pub optional_headers: OptionalHeaderPe32Plus,
    pub data_directories: Vec<DataDirectory>,
}

impl HeadersPe32 {
    pub fn new(coff_header: CoffHeader, optional_headers: OptionalHeaderPe32, data_directories: Vec<DataDirectory>) -> Self {
        HeadersPe32 {
            coff_header,
            optional_headers,
            data_directories,
        }
    }
}

impl HeadersPe32Plus {
    pub fn new(coff_header: CoffHeader, optional_headers: OptionalHeaderPe32Plus, data_directories: Vec<DataDirectory>) -> Self {
        HeadersPe32Plus {
            coff_header,
            optional_headers,
            data_directories,
        }
    }
}

impl PEHeader for CoffHeader {
    fn coff_header(&self) -> &CoffHeader {
        &self
    }

    fn optional_header_pe32(&self) -> Option<&OptionalHeaderPe32> {
        None
    }

    fn optional_header_pe32plus(&self) -> Option<&OptionalHeaderPe32Plus> {
        None
    }

    fn data_directories(&self) -> Option<&Vec<DataDirectory>> {
        None
    }
}

impl PEHeader for HeadersPe32 {
    fn coff_header(&self) -> &CoffHeader {
        &self.coff_header
    }

    fn optional_header_pe32(&self) -> Option<&OptionalHeaderPe32> {
        Some(&self.optional_headers)
    }

    fn optional_header_pe32plus(&self) -> Option<&OptionalHeaderPe32Plus> {
        None
    }

    fn data_directories(&self) -> Option<&Vec<DataDirectory>> {
        Some(&self.data_directories)
    }
}

impl PEHeader for HeadersPe32Plus {
    fn coff_header(&self) -> &CoffHeader {
        &self.coff_header
    }

    fn optional_header_pe32(&self) -> Option<&OptionalHeaderPe32> {
        None
    }

    fn optional_header_pe32plus(&self) -> Option<&OptionalHeaderPe32Plus> {
        Some(&self.optional_headers)
    }

    fn data_directories(&self) -> Option<&Vec<DataDirectory>> {
        Some(&self.data_directories)
    }
}

impl Display for MachineType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Unknown => write!(f, "Unknown/Any"),
            Self::Alpha => write!(f, "Alpha AXP 32-bit"),
            Self::Alpha64 => write!(f, "Alpha AXP 64-bit"),
            Self::Am33 => write!(f, "Matsushita AM33"),
            Self::Amd64 => write!(f, "x64"),
            Self::Arm => write!(f, "ARM little endian"),
            Self::Arm64 => write!(f, "ARM64 little endian"),
            Self::ArmNT => write!(f, "ARM Thumb-2 little endian"),
            Self::Ebc => write!(f, "EFI byte code"),
            Self::I386 => write!(f, "Intel 386 or later/compatible processors"),
            Self::Ia64 => write!(f, "Intel Itanium processor family"),
            Self::LoongArch32 => write!(f, "LoongArch 32-bit processor family"),
            Self::LoongArch64 => write!(f, "LoongArch 64-bit processor family"),
            Self::M32R => write!(f, "Mitsubishi M32R little endian"),
            Self::Mips16 => write!(f, "MIPS16"),
            Self::MipsFpu => write!(f, "MIPS with FPU"),
            Self::MipsFpu16 => write!(f, "MIPS16 with FPU"),
            Self::PowerPc => write!(f, "Power PC little endian"),
            Self::PowerPcFp => write!(f, "Power PC with floating point support"),
            Self::R4000 => write!(f, "MIPS little endian"),
            Self::RiscV32 => write!(f, "RISC-V 32-bit"),
            Self::RiscV64 => write!(f, "RISC-V 64-bit"),
            Self::RiscV128 => write!(f, "RISC-V 128-bit"),
            Self::Sh3 => write!(f, "Hitachi SH3"),
            Self::Sh3Dsp => write!(f, "Hitachi SH3 DSP"),
            Self::Sh4 => write!(f, "Hitachi SH4"),
            Self::Sh5 => write!(f, "Hitachi SH5"),
            Self::Thumb => write!(f, "Thumb"),
            Self::WceMipsV2 => write!(f, "MIPS little-endian WCE v2"),
        }
    }
}

impl Display for WindowsSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Native => write!(f, "Device driver / native Windows process"),
            Self::WindowsGui => write!(f, "Windows GUI"),
            Self::WindowsCui => write!(f, "Windows CUI"),
            Self::Os2Cui => write!(f, "OS/2 CUI"),
            Self::PosixCui => write!(f, "POSIX CUI"),
            Self::NativeWindows => write!(f, "Native Win9x driver"),
            Self::WindowsCeGui => write!(f, "Windows CE"),
            Self::EfiApplication => write!(f, "EFI application"),
            Self::EfiBootServiceDriver => write!(f, "EFI driver with boot services"),
            Self::EfiRuntimeDriver => write!(f, "EFI driver with runtime services"),
            Self::EfiRom => write!(f, "EFI ROM"),
            Self::Xbox => write!(f, "Xbox"),
            Self::WindowsBootApplication => write!(f, "Windows boot application"),
        }
    }
}
