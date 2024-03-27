use std::fs::File;
use std::io::{self, Read, Seek};
use std::mem::transmute;

use crate::pe::err::PEError;
use crate::pe::{CoffHeader, PEHeader};

impl TryFrom<&mut File> for CoffHeader {
    type Error = PEError;

    fn try_from(value: &mut File) -> Result<Self, Self::Error> {
        match get_header(value) {
            Ok(header) => Ok(header),
            Err(e) => Err(PEError::DeserialiseError),
        }
    }
}

fn get_header(fh: &mut File) -> io::Result<CoffHeader> {
    let metadata = fh.metadata()?;
    let len = metadata.len();

    // if len < 0x3f, then not PE -- 0x3c is where the dword header pointer is
    if len < 0x3f {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing header pointer"));
    }

    let header_addr = get_header_address(fh)?;
    let bytes = get_header_bytes(fh, header_addr as u64)?;
    let header: CoffHeader = unsafe { transmute(bytes) }; // TODO this is amusing but extremely bad :-)
    Ok(header)
}

fn get_header_address(fh: &mut File) -> io::Result<u32> {
    let mut header_addr_bytes: [u8; 4] = [0_u8; 4];
    let seek_pos = fh.seek(io::SeekFrom::Start(0x3c))?;
    assert!(seek_pos == 0x3c, "seek failed!!"); // TODO this can be an EOF error!!
    let bytes_read = fh.read(&mut header_addr_bytes)?;
    if bytes_read != 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF while reading header address"));
    }
    Ok(u32::from_le_bytes(header_addr_bytes) + 4)
}

fn get_header_bytes(fh: &mut File, addr: u64) -> io::Result<[u8; 20]> {
    let mut header_bytes: [u8; 20] = [0_u8; 20];
    let seek_pos = fh.seek(io::SeekFrom::Start(addr))?;
    assert!(seek_pos == addr, "seek failed!!"); // TODO this can be an EOF error!!
    let bytes_read = fh.read(&mut header_bytes)?;
    if bytes_read != 20 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF while reading header"));
    }
    Ok(header_bytes)
}
