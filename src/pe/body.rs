use bitflags::bitflags;

bitflags! {
    /// PE section characteristic flags given in the section headers.
    #[derive(Debug, Clone, Copy)]
    pub struct SectionFlags: u32 {
        const TypeNoPad = 0x00000008;
        const CntCode = 0x00000020;
        const CntInitialisedData = 0x00000040;
        const CntUninitialisedData = 0x00000080;
        const LnkOther = 0x00000100;
        const LnkInfo = 0x00000200;
        const LnkRemove = 0x00000800;
        const LnkComdat = 0x00001000;
        const Gprel = 0x00008000;
        const MemPurgeableOrMem16Bit = 0x00020000;
        const MemLocked = 0x00040000;
        const MemPreload = 0x00080000;
        const Align1Bytes = 0x00100000;
        const Align2Bytes = 0x00200000;
        const Align4Bytes = 0x00300000;
        const Align8Bytes = 0x00400000;
        const Align16Bytes = 0x00500000;
        const Align32Bytes = 0x00600000;
        const Align64Bytes = 0x00700000;
        const Align128Bytes = 0x00800000;
        const Align256Bytes = 0x0090000;
        const Align512Bytes = 0x00A00000;
        const Align1024Bytes = 0x00B00000;
        const Align2048Bytes = 0x00C00000;
        const Align4096Bytes = 0x00D00000;
        const Align8192Bytes = 0x00E00000;
        const LnkNrelocOvfl = 0x01000000;
        const MemDiscardable = 0x02000000;
        const MemNotCached = 0x04000000;
        const MemNotPaged = 0x08000000;
        const MemShared = 0x10000000;
        const MemExecute = 0x20000000;
        const MemRead = 0x40000000;
        const MemWrite = 0x80000000;
    }
}

/// A row from the section table.
#[repr(C)]
#[derive(Debug)]
pub struct SectionHeader {
    pub name: [u8; 8], // TODO string of fixed size?
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: SectionFlags,
}
