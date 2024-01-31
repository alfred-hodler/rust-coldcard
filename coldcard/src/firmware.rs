//! Firmware and upgrade related module.
use std::fs::File;
use std::io::{self, SeekFrom};
use std::path::Path;

pub const FW_HEADER_SIZE: u64 = 128;
pub const FW_HEADER_OFFSET: u64 = 0x4000 - FW_HEADER_SIZE;
pub const FW_HEADER_MAGIC: u32 = 0xCC001234;

/// Firmware bytes, ready to upload to Coldcard.
#[derive(Debug)]
pub struct Firmware(Vec<u8>);

impl Firmware {
    /// Loads a DFU file and parses it into a ready-to-upload Coldcard firmware.
    pub fn load_dfu(path: &Path) -> Result<Firmware, Error> {
        let mut file = File::open(path)?;

        Self::parse_dfu(&mut file)
    }

    /// Parses DFU formatted bytes into a ready-to-upload Coldcard firmware.
    pub fn parse_dfu<T: io::Read + io::Seek>(stream: &mut T) -> Result<Firmware, Error> {
        let mut prefix = [0_u8; 11];
        stream.read_exact(&mut prefix)?;

        let signature = &prefix[0..5];
        let _version = prefix[5];
        let _size = &prefix[6..10];
        let targets = prefix[10];

        if signature != b"DfuSe" {
            return Err(Error::NotDFU);
        }

        for _ in 0..targets {
            let mut tprefix = [0_u8; 274];
            stream.read_exact(&mut tprefix)?;

            let signature = &tprefix[0..6];
            let _altsetting = tprefix[6];
            let _named = &tprefix[7..11];
            let _name = &tprefix[11..266];
            let _size = &tprefix[266..270];
            let elements = &tprefix[270..274];

            if signature != b"Target" {
                return Err(Error::NotDFU);
            }

            let elements = decode_u32(Some(elements))?;

            if (0..elements).next().is_some() {
                let mut eprefix = [0_u8; 8];
                stream.read_exact(&mut eprefix)?;
                let size = decode_u32(eprefix.get(4..8))?;

                if size % 256 != 0 {
                    return Err(Error::UnalignedSize);
                }

                let offset = stream.stream_position()?;
                stream.seek(SeekFrom::Start(offset + FW_HEADER_OFFSET))?;
                let mut header = [0_u8; FW_HEADER_SIZE as usize];
                stream.read_exact(&mut header)?;

                let magic = decode_u32(header.get(0..4))?;
                if magic != FW_HEADER_MAGIC {
                    return Err(Error::BadHeaderMagic);
                }

                stream.seek(SeekFrom::Start(offset))?;
                let mut data = vec![0_u8; size as usize];
                stream.read_exact(&mut data)?;
                data.extend_from_slice(&header);

                return Ok(Firmware(data));
            }
        }

        Err(Error::UnknownFirmwareOffset)
    }

    /// Firmware bytes after DFU parsing.
    pub fn bytes(&self) -> &[u8] {
        &self.0
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
