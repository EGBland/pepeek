use std::fmt::Display;

use bitflags::bitflags;

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

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct Characteristics: u16 {
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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PEHeader {
    pub target_machine: MachineType,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: Characteristics,
}
