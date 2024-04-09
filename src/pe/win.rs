use std::fs::File;
use std::io;
use std::mem::{size_of, transmute};
use std::os::windows::fs::FileExt;

use super::body::export::ExportDirectoryTable;
use super::body::SectionHeader;
use super::err::PEError;
use super::headers::{CoffHeader, DataDirectory, Headers, HeadersPe32, HeadersPe32Plus, OptionalHeaderPe32, OptionalHeaderPe32Plus, PEType};
use super::traits::PEHeader;

pub fn get_headers_from_file(fh: &File) -> Result<Headers, PEError> {
    match do_get_headers_from_file(fh) {
        Ok(header) => Ok(header),
        Err(err) => Err(PEError::DeserialiseError(err.to_string())),
    }
}

pub fn get_section_table(fh: &File, headers: &(impl PEHeader + ?Sized)) -> Result<Vec<SectionHeader>, PEError> {
    match get_section_headers(fh, headers.coff_header()) {
        Ok(section_table) => Ok(section_table),
        Err(err) => Err(PEError::DeserialiseError(err.to_string())),
    }
}

pub fn get_export_table(fh: &File, section_table: &Vec<SectionHeader>) -> Result<ExportDirectoryTable, PEError> {
    todo!()
}

pub fn rva_to_file_ptr(rva: u32, sections: &Vec<SectionHeader>) -> Option<u32> {
    for section in sections {
        let section_virtual_begin = section.virtual_address;
        let section_virtual_end = section_virtual_begin + section.virtual_size;
        let section_file_ptr = section.pointer_to_raw_data;

        if section_virtual_begin <= rva && rva <= section_virtual_end {
            return Some(rva - section_virtual_begin + section_file_ptr);
        }
    }
    
    None
}

fn do_get_headers_from_file(fh: &File) -> io::Result<Headers> {
    let base_addr = get_base_addr(&fh)?;
    let coff_header_addr = get_coff_header_address(&fh)?;
    let coff_header = get_coff_header(fh)?;

    if coff_header.size_of_optional_header == 0 {
        // no optional header, just return the COFF header
        return Ok(Headers::from_coff(base_addr, coff_header));
    } else {
        // get optional headers, then return the full set of headers
        let magic_option = get_optional_headers_magic(fh, coff_header_addr, &coff_header)?;
        match magic_option {
            Some(PEType::Pe32) => {
                let optional_headers = get_optional_headers_pe32(fh, coff_header_addr, &coff_header)?;
                let data_directories = get_data_directories_pe32(fh, coff_header_addr, &optional_headers)?;
                let full_headers = HeadersPe32::new(coff_header, optional_headers, data_directories);
                return Ok(Headers::from_pe32(base_addr, coff_header, full_headers));
            }
            Some(PEType::Pe32Plus) => {
                let optional_headers = get_optional_headers_pe32plus(fh, coff_header_addr, &coff_header)?;
                let data_directories = get_data_directories_pe32plus(fh, coff_header_addr, &optional_headers)?;
                let full_headers = HeadersPe32Plus::new(coff_header, optional_headers, data_directories);
                return Ok(Headers::from_pe32plus(base_addr, coff_header, full_headers));
            }
            None => panic!("invalid/missing magic number for optional header!!"),
        }
    }
}

fn get_section_headers(fh: &File, coff_header: &CoffHeader) -> io::Result<Vec<SectionHeader>> {
    let coff_addr = get_coff_header_address(fh)?;
    let section_base_addr = coff_addr + 20 + (coff_header.size_of_optional_header as u32);
    let num_sections = coff_header.number_of_sections;

    let mut ret: Vec<SectionHeader> = Vec::with_capacity(num_sections as usize);
    let mut section_addr = section_base_addr;
    for _ in 0..num_sections {
        let mut section_header_bytes: [u8; 40] = [0_u8; 40];
        let bytes_read = fh.seek_read(&mut section_header_bytes, section_addr as u64)?;
        if bytes_read != 40 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF while reading section header"));
        }
        let section_header: SectionHeader = unsafe { transmute(section_header_bytes) };
        ret.push(section_header);
        section_addr += size_of::<SectionHeader>() as u32;
    }
    Ok(ret)
}

fn get_data_directories_pe32(fh: &File, coff_addr: u32, headers: &OptionalHeaderPe32) -> io::Result<Vec<DataDirectory>> {
    let num_directories = headers.windows_fields.number_of_rva_and_sizes;
    let base_addr = coff_addr + 20 + 96; // +20 for coff header, +96 for pe32 optional headers
    get_data_directories(fh, base_addr, num_directories)
}

fn get_data_directories_pe32plus(fh: &File, coff_addr: u32, headers: &OptionalHeaderPe32Plus) -> io::Result<Vec<DataDirectory>> {
    let num_directories = headers.windows_fields.number_of_rva_and_sizes;
    let base_addr = coff_addr + 20 + 112; // +20 for coff header, +112 for pe32+ optional headers
    get_data_directories(fh, base_addr, num_directories)
}

fn get_data_directories(fh: &File, base_addr: u32, num_directories: u32) -> io::Result<Vec<DataDirectory>> {
    let mut ret: Vec<DataDirectory> = Vec::with_capacity(num_directories as usize);
    let mut addr = base_addr;
    for _ in 0..num_directories {
        let mut dir_bytes: [u8; 8] = [0_u8; 8];
        let bytes_read = fh.seek_read(&mut dir_bytes, addr as u64)?;
        if bytes_read != 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF while reading data directory"));
        }
        let dir: DataDirectory = unsafe { transmute(dir_bytes) };
        ret.push(dir);
        addr += size_of::<DataDirectory>() as u32;
    }
    Ok(ret)
}

fn get_optional_headers_pe32(fh: &File, coff_addr: u32, coff_header: &CoffHeader) -> io::Result<OptionalHeaderPe32> {
    let mut headers_bytes: [u8; 96] = [0_u8; 96];
    let optional_addr = get_optional_headers_addr(coff_addr, &coff_header).unwrap();
    let bytes_read = fh.seek_read(&mut headers_bytes, optional_addr as u64)?;
    if bytes_read != 96 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF while reading optional headers"));
    }
    let headers = unsafe { transmute(headers_bytes) }; // TODO this probably won't work
    Ok(headers)
}

fn get_optional_headers_pe32plus(fh: &File, coff_addr: u32, coff_header: &CoffHeader) -> io::Result<OptionalHeaderPe32Plus> {
    let mut headers_bytes: [u8; 112] = [0_u8; 112];
    let optional_addr = get_optional_headers_addr(coff_addr, &coff_header).unwrap();
    let bytes_read = fh.seek_read(&mut headers_bytes, optional_addr as u64)?;
    if bytes_read != 112 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF while reading optional headers"));
    }
    let headers = unsafe { transmute(headers_bytes) }; // TODO this probably won't work
    Ok(headers)
}

fn get_coff_header(fh: &File) -> io::Result<CoffHeader> {
    let metadata = fh.metadata()?;
    let len = metadata.len();

    // if len < 0x3f, then not PE -- 0x3c is where the dword header pointer is
    if len < 0x3f {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing header pointer"));
    }

    let header_addr = get_coff_header_address(fh)?;
    let bytes = get_coff_header_bytes(fh, header_addr)?;
    let header: CoffHeader = unsafe { transmute(bytes) }; // TODO this is amusing but extremely bad :-)
    Ok(header)
}

fn get_optional_headers_addr(coff_addr: u32, coff_header: &CoffHeader) -> Option<u32> {
    if coff_header.size_of_optional_header == 0 {
        return None;
    } else {
        return Some(coff_addr + 20);
    }
}

fn get_optional_headers_magic(fh: &File, coff_addr: u32, coff_header: &CoffHeader) -> io::Result<Option<PEType>> {
    let addr_option = get_optional_headers_addr(coff_addr, coff_header);
    if let Some(addr) = addr_option {
        let mut magic_bytes: [u8; 2] = [0_u8; 2];
        let bytes_read = fh.seek_read(&mut magic_bytes, addr as u64)?;
        if bytes_read != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reached EOF while reading optional headers magic number",
            ));
        }
        let magic: u16 = u16::from_le_bytes(magic_bytes);
        return match magic {
            0x10b => Ok(Some(PEType::Pe32)),
            0x20b => Ok(Some(PEType::Pe32Plus)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "magic number not recognised as PE32 or PE32+")),
        };
    } else {
        return Ok(None);
    }
}

fn get_base_addr(fh: &File) -> io::Result<u32> {
    let mut header_addr_bytes: [u8; 4] = [0_u8; 4];
    let bytes_read = fh.seek_read(&mut header_addr_bytes, 0x3c)?;
    if bytes_read != 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF while reading header address"));
    }
    Ok(u32::from_le_bytes(header_addr_bytes))
}

fn get_coff_header_address(fh: &File) -> io::Result<u32> {
    Ok(get_base_addr(fh)? + 4)
}

fn get_coff_header_bytes(fh: &File, addr: u32) -> io::Result<[u8; 20]> {
    let mut header_bytes: [u8; 20] = [0_u8; 20];
    let bytes_read = fh.seek_read(&mut header_bytes, addr as u64)?;
    if bytes_read != 20 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF while reading header"));
    }
    Ok(header_bytes)
}
