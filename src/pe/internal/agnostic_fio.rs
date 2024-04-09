use std::fs::File;
use std::io;
#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom};
#[cfg(windows)]
use std::os::windows::fs::FileExt;

#[cfg(windows)]
pub fn read_exact<const N: usize>(fh: &mut File, offset: u64) -> io::Result<[u8; N]> {
    let mut buf: [u8; N] = [0_u8; N];
    let bytes_read = fh.seek_read(&mut buf, offset as u64)?;
    if bytes_read != N {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reached EOF early in read_exact"));
    }
    Ok(buf)
}

#[cfg(unix)]
pub fn read_exact<const N: usize>(fh: &mut File, offset: u64) -> io::Result<[u8; N]> {
    let mut buf: [u8; N] = [0_u8; N];
    let seek_pos = fh.seek(SeekFrom::Start(offset))?;
    if seek_pos != offset {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Seek failed in read_exact"));
    }

    let bytes_read = fh.read(&mut buf)?;
    if bytes_read != N {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Reached EOF early in read_exact"));
    }

    Ok(buf)
}
