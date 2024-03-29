use super::body::SectionHeader;
use super::err::PEError;
use super::headers::{CoffHeader, DataDirectory, HeadersPe32, HeadersPe32Plus, OptionalHeaderPe32, OptionalHeaderPe32Plus, PEType};
use super::internal::agnostic_fio::read_exact;
use super::traits::PEHeader;
use std::fs::File;
use std::io;
use std::mem::{size_of, transmute};

pub fn get_headers_from_file(fh: &mut File) -> Result<Box<dyn PEHeader>, PEError> {
    match do_get_headers_from_file(fh) {
        Ok(header) => Ok(header),
        Err(err) => Err(PEError::DeserialiseError(err.to_string())),
    }
}

pub fn get_section_table(fh: &mut File, headers: &(impl PEHeader + ?Sized)) -> Result<Vec<SectionHeader>, PEError> {
    match get_section_headers(fh, headers.coff_header()) {
        Ok(section_table) => Ok(section_table),
        Err(err) => Err(PEError::DeserialiseError(err.to_string())),
    }
}

fn do_get_headers_from_file(fh: &mut File) -> io::Result<Box<dyn PEHeader>> {
    let coff_header_addr = get_coff_header_address(fh)?;
    let coff_header = get_coff_header(fh)?;

    if coff_header.size_of_optional_header == 0 {
        // no optional header, just return the COFF header
        return Ok(Box::new(coff_header));
    } else {
        // get optional headers, then return the full set of headers
        let magic_option = get_optional_headers_magic(fh, coff_header_addr, &coff_header)?;
        match magic_option {
            Some(PEType::Pe32) => {
                let optional_headers = get_optional_headers_pe32(fh, coff_header_addr, &coff_header)?;
                let data_directories = get_data_directories_pe32(fh, coff_header_addr, &optional_headers)?;
                let full_headers = HeadersPe32::new(coff_header, optional_headers, data_directories);
                return Ok(Box::new(full_headers));
            }
            Some(PEType::Pe32Plus) => {
                let optional_headers = get_optional_headers_pe32plus(fh, coff_header_addr, &coff_header)?;
                let data_directories = get_data_directories_pe32plus(fh, coff_header_addr, &optional_headers)?;
                let full_headers = HeadersPe32Plus::new(coff_header, optional_headers, data_directories);
                return Ok(Box::new(full_headers));
            }
            None => panic!("invalid/missing magic number for optional header!!"),
        }
    }
}

fn get_section_headers(fh: &mut File, coff_header: &CoffHeader) -> io::Result<Vec<SectionHeader>> {
    let coff_addr = get_coff_header_address(fh)?;
    let section_base_addr = coff_addr + 20 + (coff_header.size_of_optional_header as u32);
    let num_sections = coff_header.number_of_sections;

    let mut ret: Vec<SectionHeader> = Vec::with_capacity(num_sections as usize);
    let mut section_addr = section_base_addr;
    for _ in 0..num_sections {
        let section_header: SectionHeader = unsafe { transmute(read_exact::<{ size_of::<SectionHeader>() }>(fh, section_addr as u64)?) };
        ret.push(section_header);
        section_addr += size_of::<SectionHeader>() as u32;
    }
    Ok(ret)
}

fn get_data_directories_pe32(fh: &mut File, coff_addr: u32, headers: &OptionalHeaderPe32) -> io::Result<Vec<DataDirectory>> {
    let num_directories = headers.windows_fields.number_of_rva_and_sizes;
    let base_addr = coff_addr + 20 + 96; // +20 for coff header, +96 for pe32 optional headers
    get_data_directories(fh, base_addr, num_directories)
}

fn get_data_directories_pe32plus(fh: &mut File, coff_addr: u32, headers: &OptionalHeaderPe32Plus) -> io::Result<Vec<DataDirectory>> {
    let num_directories = headers.windows_fields.number_of_rva_and_sizes;
    let base_addr = coff_addr + 20 + 112; // +20 for coff header, +112 for pe32+ optional headers
    get_data_directories(fh, base_addr, num_directories)
}

fn get_data_directories(fh: &mut File, base_addr: u32, num_directories: u32) -> io::Result<Vec<DataDirectory>> {
    let mut ret: Vec<DataDirectory> = Vec::with_capacity(num_directories as usize);
    let mut addr = base_addr;
    for _ in 0..num_directories {
        let dir: DataDirectory = unsafe { transmute(read_exact::<{ size_of::<DataDirectory>() }>(fh, addr as u64)?) };
        ret.push(dir);
        addr += size_of::<DataDirectory>() as u32;
    }
    Ok(ret)
}

fn get_optional_headers_pe32(fh: &mut File, coff_addr: u32, coff_header: &CoffHeader) -> io::Result<OptionalHeaderPe32> {
    let optional_addr = get_optional_headers_addr(coff_addr, &coff_header).unwrap();
    let headers = unsafe { transmute(read_exact::<{ size_of::<OptionalHeaderPe32>() }>(fh, optional_addr as u64)?) };
    Ok(headers)
}

fn get_optional_headers_pe32plus(fh: &mut File, coff_addr: u32, coff_header: &CoffHeader) -> io::Result<OptionalHeaderPe32Plus> {
    let optional_addr = get_optional_headers_addr(coff_addr, &coff_header).unwrap();
    let headers = unsafe { transmute(read_exact::<{ size_of::<OptionalHeaderPe32Plus>() }>(fh, optional_addr as u64)?) };
    Ok(headers)
}

fn get_coff_header(fh: &mut File) -> io::Result<CoffHeader> {
    let metadata = fh.metadata()?;
    let len = metadata.len();

    // if len < 0x3f, then not PE -- 0x3c is where the dword header pointer is
    if len < 0x3f {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing header pointer"));
    }

    let header_addr = get_coff_header_address(fh)?;
    let header: CoffHeader = unsafe { transmute(read_exact::<{ size_of::<CoffHeader>() }>(fh, header_addr as u64)?) };
    Ok(header)
}

fn get_optional_headers_addr(coff_addr: u32, coff_header: &CoffHeader) -> Option<u32> {
    if coff_header.size_of_optional_header == 0 {
        return None;
    } else {
        return Some(coff_addr + 20);
    }
}

fn get_optional_headers_magic(fh: &mut File, coff_addr: u32, coff_header: &CoffHeader) -> io::Result<Option<PEType>> {
    let addr_option = get_optional_headers_addr(coff_addr, coff_header);
    if let Some(addr) = addr_option {
        let magic: u16 = u16::from_le_bytes(read_exact(fh, addr as u64)?);
        return match magic {
            0x10b => Ok(Some(PEType::Pe32)),
            0x20b => Ok(Some(PEType::Pe32Plus)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "magic number not recognised as PE32 or PE32+")),
        };
    } else {
        return Ok(None);
    }
}

fn get_coff_header_address(fh: &mut File) -> io::Result<u32> {
    Ok(u32::from_le_bytes(read_exact(fh, 0x3c)?) + 4)
}
