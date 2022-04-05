//! Firmware and upgrade related module.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const FW_HEADER_SIZE: u64 = 128;
pub const FW_HEADER_OFFSET: u64 = 0x4000 - FW_HEADER_SIZE;
pub const FW_HEADER_MAGIC: u32 = 0xCC001234;

/// Firmware bytes, ready to upload.
#[derive(Debug)]
pub struct Firmware(pub Vec<u8>);

impl Firmware {
    /// Loads and prepares firmware bytes in a ready-to-upload form.
    /// Works only with DFU files.
    pub fn load_dfu(path: &Path) -> Result<Firmware, Error> {
        let mut file = File::open(path)?;
        file.rewind()?;

        let mut prefix = vec![0_u8; 11];
        file.read_exact(&mut prefix)?;

        let signature = &prefix[0..5];
        let targets = prefix[10];

        if signature != b"DfuSe" {
            return Err(Error::NotDFU);
        }

        let mut two_u32 = vec![0_u8; 8];

        for _ in 0..targets {
            file.seek(SeekFrom::Current(266))?;
            file.read_exact(&mut two_u32)?;
            let elements = decode_u32(two_u32.get(4..8))?;

            for _ in 0..elements {
                file.read_exact(&mut two_u32)?;
                let addr = decode_u32(two_u32.get(0..4))?;
                let size = decode_u32(two_u32.get(4..8))?;

                if size % 256 != 0 {
                    return Err(Error::UnalignedSize);
                }

                if addr > 0x8008000 {
                    return Err(Error::BadAddress);
                }

                let offset = file.stream_position()?;
                file.seek(SeekFrom::Start(offset + FW_HEADER_OFFSET))?;
                let mut header = vec![0_u8; FW_HEADER_SIZE as usize];
                file.read_exact(&mut header)?;

                let magic = decode_u32(header.get(0..4))?;
                if magic != FW_HEADER_MAGIC {
                    return Err(Error::BadHeaderMagic);
                }

                file.seek(SeekFrom::Start(offset))?;
                let mut data = vec![0_u8; size as usize];
                file.read_exact(&mut data)?;
                data.extend_from_slice(&header);

                return Ok(Firmware(data));
            }
        }

        Err(Error::UnknownFirmwareOffset)
    }
}

/// Firmware error.
#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    DecodeFromBytes(&'static str),
    NotDFU,
    BadAddress,
    UnknownFirmwareOffset,
    BadHeaderMagic,
    UnalignedSize,
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::IO(error)
    }
}

fn decode_u32(bytes: Option<&[u8]>) -> Result<u32, Error> {
    match bytes {
        Some(bytes) if bytes.len() == 4 => Ok(u32::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| Error::DecodeFromBytes("u32"))?,
        )),
        _ => Err(Error::DecodeFromBytes("u32")),
    }
}
