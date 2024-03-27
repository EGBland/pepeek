use std::fs::File;
use std::io; 
use std::mem::transmute;
use std::os::windows::fs::FileExt;

use crate::pe::CoffHeader;

fn get_header(fh: &File) -> io::Result<CoffHeader> {
    let metadata = fh.metadata()?;
    let len = metadata.len();

    // if len < 0x3f, then not PE -- 0x3c is where the dword header pointer is
    if len < 0x3f {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing header pointer",
        ));
    }

    let header_addr = get_header_address(fh)?;
    let bytes = get_header_bytes(fh, header_addr)?;
    let header: CoffHeader = unsafe { transmute(bytes) }; // TODO this is amusing but extremely bad :-)
    Ok(header)
}

fn get_header_address(fh: &File) -> io::Result<u32> {
    let mut header_addr_bytes: [u8; 4] = [0_u8; 4];
    let bytes_read = fh.seek_read(&mut header_addr_bytes, 0x3c)?;
    if bytes_read != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reached EOF while reading header address",
        ));
    }
    Ok(u32::from_le_bytes(header_addr_bytes) + 4)
}

fn get_header_bytes(fh: &File, addr: u32) -> io::Result<[u8; 20]> {
    let mut header_bytes: [u8; 20] = [0_u8; 20];
    let bytes_read = fh.seek_read(&mut header_bytes, addr as u64)?;
    if bytes_read != 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reached EOF while reading header",
        ));
    }
    Ok(header_bytes)
}
