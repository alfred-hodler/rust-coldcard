pub mod derivation_path;

pub use derivation_path::DerivationPath;

use crate::constants::*;
use enum_as_inner::EnumAsInner;

macro_rules! impl_new_with_range {
    ($thing:ident, $range:expr) => {
        impl_new_with_range!($thing, $range, 0_u8..);
    };
    ($thing:ident, $range:expr, $valid_char_range:expr) => {
        impl $thing {
            pub fn new(value: impl AsRef<[u8]>) -> Result<Self, EncodeError> {
                let value = value.as_ref();
                for c in value {
                    if !$valid_char_range.contains(c) {
                        return Err(EncodeError::InvalidCharValue);
                    }
                }
                let type_name = std::any::type_name::<$thing>();
                #[allow(unused_comparisons)]
                if value.len() < $range.start || value.len() > $range.end {
                    return Err(EncodeError::LengthMismatch(type_name, value.len()));
                }
                Ok(Self(value.to_owned()))
            }
        }
    };
}

pub struct Upload(Vec<u8>);
pub struct Message(Vec<u8>);
pub struct Username(Vec<u8>);
pub struct AuthToken(Vec<u8>);

#[derive(Default)]
pub struct Secret(Vec<u8>);
pub struct RedeemScript(Vec<u8>);
pub struct Passphrase(Vec<u8>);

pub struct HsmStartParams {
    pub length: u32,
    pub file_sha: [u8; 32],
}

pub struct XfpPath {
    pub fingerprint: u32,
    pub path: DerivationPath,
}

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum FileNo {
    Zero = 0,
    One = 1,
}

impl Default for FileNo {
    fn default() -> Self {
        Self::One
    }
}

impl_new_with_range!(Upload, 1..MAX_BLK_LEN);
impl_new_with_range!(Message, 1..240);
impl_new_with_range!(Username, 1..16);
impl_new_with_range!(AuthToken, 6..32);
impl_new_with_range!(RedeemScript, 30..520);
impl_new_with_range!(Passphrase, 0..100, 32..=126);

impl Secret {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, EncodeError> {
        let value = value.as_ref();
        match value.len() {
            0 | 10 | 20 | 32 => Ok(Self(value.to_owned())),
            _ => Err(EncodeError::LengthNotOneOf("Secret", vec![0, 10, 20, 32])),
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum AddressFormat {
    P2PKH = AFC_PUBKEY,
    P2SH = AFC_SCRIPT,
    P2WPKH = AFC_PUBKEY | AFC_SEGWIT | AFC_BECH32,
    P2WSH = AFC_SCRIPT | AFC_SEGWIT | AFC_BECH32,
    P2WPKH_P2SH = AFC_WRAPPED | AFC_PUBKEY | AFC_SEGWIT,
    P2WSH_P2SH = AFC_WRAPPED | AFC_SCRIPT | AFC_SEGWIT,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum AuthMode {
    TOTP = 0x01,
    HOTP = 0x02,
    HMAC = 0x03,
}

/// Request variants that can be sent to a Coldcard.
pub enum Request {
    Logout,
    Reboot,
    Version,
    Ping(Vec<u8>),
    Bip39Passphrase(Passphrase),
    GetPassphraseDone,
    CheckMitm,
    StartBackup,
    EncryptStart {
        device_pubkey: [u8; 64],
        version: Option<u32>,
    },
    Upload {
        offset: u32,
        total_size: u32,
        data: Upload,
    },
    Download {
        offset: u32,
        length: u32,
        file_number: FileNo,
    },
    Sha256,
    SignTransaction {
        length: u32,
        file_sha: [u8; 32],
        flags: Option<u32>,
    },
    SignMessage {
        raw_msg: Message,
        subpath: Option<DerivationPath>,
        addr_fmt: AddressFormat,
    },
    GetSignedMessage,
    GetBackupFile,
    GetSignedTransaction,
    MultisigEnroll {
        length: u32,
        file_sha: [u8; 32],
    },
    MultiSigCheck {
        m: u32,
        n: u32,
        xfp_xor: u32,
    },
    GetXPub(Option<DerivationPath>),
    ShowAddress {
        subpath: DerivationPath,
        addr_fmt: AddressFormat,
    },
    ShowP2SHAddress {
        min_signers: u8,
        xfp_paths: Vec<XfpPath>,
        redeem_script: RedeemScript,
        address_format: AddressFormat,
    },
    Blockchain,
    BagNumber(Option<String>),
    HsmStart(Option<HsmStartParams>),
    HsmStatus,
    CreateUser {
        username: Username,
        auth_mode: AuthMode,
        secret: Option<Secret>,
        show_qr: bool,
    },
    DeleteUser(Username),
    UserAuth {
        username: Username,
        token: AuthToken,
        totp_time: u32,
    },
    GetStorageLocker,
}

impl Request {
    /// Encodes a `Request` into a byte vector.
    pub fn encode(self) -> Vec<u8> {
        match self {
            Request::Logout => cmd("logo"),

            Request::Reboot => cmd("rebo"),

            Request::Version => cmd("vers"),

            Request::Ping(msg) => {
                let mut buf = cmd("ping");
                buf.extend(msg);
                buf
            }

            Request::Bip39Passphrase(pw) => {
                let mut buf = cmd("pass");
                buf.extend(pw.0);
                buf
            }

            Request::GetPassphraseDone => cmd("pwok"),

            Request::CheckMitm => cmd("mitm"),

            Request::StartBackup => cmd("back"),

            Request::EncryptStart {
                device_pubkey,
                version,
            } => {
                let mut buf = cmd("ncry");
                buf.extend(version.unwrap_or(1).to_le_bytes());
                buf.extend(device_pubkey);
                buf
            }

            Request::Upload {
                offset,
                total_size,
                data,
            } => {
                let mut buf = cmd("upld");
                buf.extend(offset.to_le_bytes());
                buf.extend(total_size.to_le_bytes());
                buf.extend(data.0);
                buf
            }

            Request::Download {
                offset,
                length,
                file_number,
            } => {
                let mut buf = cmd("dwld");
                buf.extend(offset.to_le_bytes());
                buf.extend(length.to_le_bytes());
                buf.extend((file_number as u32).to_le_bytes());
                buf
            }

            Request::Sha256 => cmd("sha2"),

            Request::SignTransaction {
                length,
                file_sha,
                flags,
            } => {
                let mut buf = cmd("stxn");
                let flags = flags.unwrap_or_default();
                buf.extend(length.to_le_bytes());
                buf.extend(flags.to_le_bytes());
                buf.extend(file_sha);
                buf
            }

            Request::SignMessage {
                raw_msg,
                subpath,
                addr_fmt,
            } => {
                let subpath = subpath.unwrap_or_default().to_string();
                let mut buf = cmd("smsg");
                buf.extend((addr_fmt as u32).to_le_bytes());
                buf.extend((subpath.len() as u32).to_le_bytes());
                buf.extend((raw_msg.0.len() as u32).to_le_bytes());
                buf.extend(subpath.as_bytes());
                buf.extend(raw_msg.0);
                buf
            }
            Request::GetSignedMessage => cmd("smok"),

            Request::GetBackupFile => cmd("bkok"),

            Request::GetSignedTransaction => cmd("stok"),

            Request::MultisigEnroll { length, file_sha } => {
                let mut buf = cmd("enrl");
                buf.extend(length.to_le_bytes());
                buf.extend(file_sha);
                buf
            }

            Request::MultiSigCheck { m, n, xfp_xor } => {
                let mut buf = cmd("msck");
                buf.extend(m.to_le_bytes());
                buf.extend(n.to_le_bytes());
                buf.extend(xfp_xor.to_le_bytes());
                buf
            }

            Request::GetXPub(subpath) => {
                let mut buf = cmd("xpub");
                buf.extend(subpath.unwrap_or_default().to_string().as_bytes());
                buf
            }

            Request::ShowAddress { subpath, addr_fmt } => {
                let mut buf = cmd("show");
                buf.extend((addr_fmt as u32).to_le_bytes());
                buf.extend(subpath.to_string().as_bytes());
                buf
            }

            Request::ShowP2SHAddress {
                min_signers,
                xfp_paths,
                redeem_script,
                address_format,
            } => {
                let mut buf = cmd("p2sh");
                buf.extend((address_format as u32).to_le_bytes());
                buf.extend((min_signers as u8).to_le_bytes());
                buf.extend((xfp_paths.len() as u8).to_le_bytes());
                buf.extend((redeem_script.0.len() as u16).to_le_bytes());
                buf.extend(redeem_script.0);

                for XfpPath { fingerprint, path } in xfp_paths {
                    buf.push((1 + path.children().len()) as u8);
                    buf.extend(fingerprint.to_le_bytes());
                    for child in path.children().into_iter() {
                        buf.extend(child.value().to_le_bytes());
                    }
                }

                buf
            }

            Request::Blockchain => cmd("blkc"),

            Request::BagNumber(number) => {
                let mut buf = cmd("bagi");
                if let Some(number) = number {
                    buf.extend(number.as_bytes());
                }
                buf
            }

            Request::HsmStart(params) => {
                let mut buf = cmd("hsms");
                if let Some(HsmStartParams { length, file_sha }) = params {
                    buf.extend(length.to_le_bytes());
                    buf.extend(file_sha);
                }
                buf
            }

            Request::HsmStatus => cmd("hsts"),

            Request::CreateUser {
                username,
                auth_mode,
                secret,
                show_qr,
            } => {
                let secret = secret.unwrap_or_default();
                let mut buf = cmd("nwur");
                buf.push((auth_mode as u8) | if show_qr { USER_AUTH_SHOW_QR } else { 0x00 });
                buf.push(username.0.len() as u8);
                buf.push(secret.0.len() as u8);
                buf.extend(username.0);
                buf.extend(secret.0);
                buf
            }

            Request::DeleteUser(username) => {
                let mut buf = cmd("rmur");
                buf.push(username.0.len() as u8);
                buf.extend(username.0);
                buf
            }

            Request::UserAuth {
                username,
                token,
                totp_time,
            } => {
                let mut buf = cmd("user");
                buf.extend(totp_time.to_le_bytes());
                buf.push(username.0.len() as u8);
                buf.push(token.0.len() as u8);
                buf.extend(username.0);
                buf.extend(token.0);
                buf
            }

            Request::GetStorageLocker => cmd("gslr"),
        }
    }
}

/// Error variants that can occur while encoding.
#[derive(Debug)]
pub enum EncodeError {
    LengthMismatch(&'static str, usize),
    LengthNotOneOf(&'static str, Vec<usize>),
    InvalidCharValue,
}

fn cmd(name: &str) -> Vec<u8> {
    name.as_bytes().to_owned()
}

/// Response variants that can be read from a Coldcard.
#[derive(Debug, EnumAsInner)]
pub enum Response {
    Ok,
    Refused,
    Busy,
    Binary(Vec<u8>),
    Int1(u32),
    Int2(u64),
    Int3(u128),
    MyPub {
        dev_pubkey: [u8; 64],
        xpub_fingerprint: [u8; 4],
        xpub: Option<String>,
    },
    Ascii(String),
    TxSigned {
        length: u32,
        sha256: [u8; 32],
    },
    MessageSigned {
        address: String,
        signature: [u8; 65],
    },
}

impl Response {
    /// Attempts to decode a byte slice into a `Response`.
    pub fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let (command, data) = split(payload, 4)?;
        match command {
            b"okay" => Ok(Response::Ok),
            b"refu" => Ok(Response::Refused),
            b"busy" => Ok(Response::Busy),
            b"biny" => Ok(Response::Binary(data.to_owned())),
            b"int1" => decode_u32(data.get(0..4)).map(|i| Response::Int1(i)),
            b"int2" => Ok(Response::Int2(decode_u64(data.get(0..8))?)),
            b"int3" => Ok(Response::Int3(decode_u128(data.get(0..12))?)),
            b"mypb" => {
                let (dev_pubkey, data) = split(data, 64)?;
                let dev_pubkey = dev_pubkey
                    .try_into()
                    .map_err(|_| DecodeError::Decode("pubkey"))?;
                let xpub_fingerprint = data
                    .get(0..4)
                    .ok_or(DecodeError::Decode("xfp wants 4 bytes"))?
                    .try_into()
                    .expect("infallible");
                let xpub_len = decode_u32(data.get(4..8))? as usize;
                let xpub = if xpub_len > 0 {
                    data.get(8..8 + xpub_len)
                        .map(|d| String::from_utf8(d.to_owned()))
                        .transpose()
                        .map_err(DecodeError::Utf8)?
                } else {
                    None
                };
                Ok(Response::MyPub {
                    dev_pubkey,
                    xpub_fingerprint,
                    xpub,
                })
            }
            b"asci" => Ok(Response::Ascii(bytes_as_string(data).map(str::to_owned)?)),
            b"strx" => {
                let (length, sha256) = split(data, 4)?;
                let length = decode_u32(Some(length))?;
                let sha256 = sha256
                    .try_into()
                    .map_err(|_| DecodeError::Decode("checksum"))?;
                Ok(Response::TxSigned { length, sha256 })
            }
            b"smrx" => {
                let (addr_len, address_and_sig) = split(data, 4)?;
                let addr_len = decode_u32(Some(addr_len))?;
                let (address, sig) = split(address_and_sig, addr_len as usize)?;
                let address = bytes_as_string(address)?.to_owned();
                let signature: [u8; 65] = sig.try_into().map_err(|_| DecodeError::Decode("sig"))?;
                Ok(Response::MessageSigned { address, signature })
            }
            b"err_" => Err(DecodeError::Protocol(
                bytes_as_string(data).map(str::to_owned)?,
            )),
            b"fram" => Err(DecodeError::Framing(
                bytes_as_string(data).map(str::to_owned)?,
            )),
            _ => Err(DecodeError::UnknownFrame(command.to_owned())),
        }
    }

    /// Attempts to convert the response into the Ok variant. Returns the Err
    /// variant with the response if something else.
    pub fn into_ok(self) -> Result<(), Response> {
        if self.is_ok() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

/// Safely decodes a possible 4 byte slice into an `u32`.
fn decode_u32(bytes: Option<&[u8]>) -> Result<u32, DecodeError> {
    match bytes {
        Some(bytes) if bytes.len() == 4 => Ok(u32::from_le_bytes(
            bytes.try_into().map_err(|_| DecodeError::Decode("u32"))?,
        )),
        _ => Err(DecodeError::Decode("u32")),
    }
}

/// Safely decodes a possible 8 byte slice into an `u64`.
fn decode_u64(bytes: Option<&[u8]>) -> Result<u64, DecodeError> {
    match bytes {
        Some(bytes) if bytes.len() == 8 => Ok(u64::from_le_bytes(
            bytes.try_into().map_err(|_| DecodeError::Decode("u64"))?,
        )),
        _ => Err(DecodeError::Decode("u64")),
    }
}

/// Safely decodes a possible 12 byte slice into an `u128`.
fn decode_u128(bytes: Option<&[u8]>) -> Result<u128, DecodeError> {
    match bytes {
        Some(bytes) if bytes.len() == 12 => Ok(u128::from_le_bytes(
            bytes
                .iter()
                .chain(&[0, 0, 0, 0])
                .cloned()
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| DecodeError::Decode("u128"))?,
        )),
        _ => Err(DecodeError::Decode("u128")),
    }
}

/// Safely splits a slice at `mid`. Returns an error if `bytes.len() < mid`.
fn split(bytes: &[u8], mid: usize) -> Result<(&[u8], &[u8]), DecodeError> {
    match bytes.len().cmp(&mid) {
        std::cmp::Ordering::Less => Err(DecodeError::Decode("unexpected slice length")),
        _ => Ok(bytes.split_at(mid)),
    }
}

/// Safely interprets a byte slice as a `String`.
fn bytes_as_string(bytes: &[u8]) -> Result<&str, DecodeError> {
    use std::str;
    str::from_utf8(bytes).map_err(|_| DecodeError::Decode("utf8"))
}

/// Error variants that can occur while decoding.
#[derive(Debug)]
pub enum DecodeError {
    UnknownFrame(Vec<u8>),
    Framing(String),
    Decode(&'static str),
    Protocol(String),
    Utf8(std::string::FromUtf8Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_test() {
        encode_eq(b"logo", Request::Logout);

        encode_eq(b"rebo", Request::Reboot);

        encode_eq(b"vers", Request::Version);

        encode_eq(b"pingHello", Request::Ping("Hello".as_bytes().to_owned()));

        encode_eq(
            b"pass123",
            Request::Bip39Passphrase(Passphrase::new("123").unwrap()),
        );

        encode_eq(
            b"pass",
            Request::Bip39Passphrase(Passphrase::new("").unwrap()),
        );

        encode_eq(b"pwok", Request::GetPassphraseDone);

        encode_eq(b"mitm", Request::CheckMitm);

        encode_eq(b"back", Request::StartBackup);

        encode_eq(
            &[
                110, 99, 114, 121, 1, 0, 0, 0, 82, 246, 129, 254, 167, 146, 135, 174, 60, 60, 152,
                151, 192, 167, 53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189, 111, 107,
                237, 24, 89, 172, 82, 246, 129, 254, 167, 146, 135, 174, 60, 60, 152, 151, 192,
                167, 53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189, 111, 107, 237, 24, 89,
                172,
            ],
            Request::EncryptStart {
                device_pubkey: BYTES_64.to_owned(),
                version: None,
            },
        );

        encode_eq(
            b"upld\x05\x00\x00\x00\x07\x00\x00\x00data 123",
            Request::Upload {
                offset: 5,
                total_size: 7,
                data: Upload::new("data 123".as_bytes().to_owned()).unwrap(),
            },
        );

        encode_eq(
            b"dwld\x05\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00",
            Request::Download {
                offset: 5,
                length: 7,
                file_number: FileNo::One,
            },
        );

        encode_eq(b"sha2", Request::Sha256);

        encode_eq(
            &[
                115, 116, 120, 110, 89, 1, 0, 0, 7, 0, 0, 0, 82, 246, 129, 254, 167, 146, 135, 174,
                60, 60, 152, 151, 192, 167, 53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189,
                111, 107, 237, 24, 89, 172,
            ],
            Request::SignTransaction {
                length: 345,
                file_sha: BYTES_32.to_owned(),
                flags: Some(STXN_FINALIZE | STXN_SIGNED | STXN_VISUALIZE),
            },
        );

        encode_eq(
            &[
                115, 109, 115, 103, 19, 0, 0, 0, 1, 0, 0, 0, 11, 0, 0, 0, 109, 72, 101, 108, 108,
                111, 32, 87, 111, 114, 108, 100,
            ],
            Request::SignMessage {
                raw_msg: Message::new("Hello World").unwrap(),
                subpath: None,
                addr_fmt: AddressFormat::P2WPKH_P2SH,
            },
        );

        encode_eq(b"smok", Request::GetSignedMessage);

        encode_eq(b"bkok", Request::GetBackupFile);

        encode_eq(b"stok", Request::GetSignedTransaction);

        encode_eq(
            &[
                101, 110, 114, 108, 99, 0, 0, 0, 82, 246, 129, 254, 167, 146, 135, 174, 60, 60,
                152, 151, 192, 167, 53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189, 111,
                107, 237, 24, 89, 172,
            ],
            Request::MultisigEnroll {
                length: 99,
                file_sha: BYTES_32.to_owned(),
            },
        );

        encode_eq(
            b"msckd\x00\x00\x00\xc8\x00\x00\x00,\x01\x00\x00",
            Request::MultiSigCheck {
                m: 100,
                n: 200,
                xfp_xor: 300,
            },
        );

        encode_eq(b"xpubm", Request::GetXPub(None));
        encode_eq(
            b"xpubm/44'/0'/0'/0/0",
            Request::GetXPub(DerivationPath::new("m/44'/0'/0'/0/0").ok()),
        );

        encode_eq(
            b"show\x07\x00\x00\x00m/44'/0'/0'/0/0",
            Request::ShowAddress {
                subpath: DerivationPath::new("m/44'/0'/0'/0/0").unwrap(),
                addr_fmt: AddressFormat::P2WPKH,
            },
        );

        encode_eq(
            &[
                112, 50, 115, 104, 8, 0, 0, 0, 5, 2, 32, 0, 82, 246, 129, 254, 167, 146, 135, 174,
                60, 60, 152, 151, 192, 167, 53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189,
                111, 107, 237, 24, 89, 172, 4, 67, 105, 5, 15, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                4, 81, 37, 21, 158, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
            ],
            Request::ShowP2SHAddress {
                min_signers: 5,
                redeem_script: RedeemScript::new(BYTES_32).unwrap(),
                xfp_paths: vec![
                    XfpPath {
                        fingerprint: 252012867,
                        path: DerivationPath::new("m/1/0/0").unwrap(),
                    },
                    XfpPath {
                        fingerprint: 2652185937,
                        path: DerivationPath::new("m/4/4/0").unwrap(),
                    },
                ],
                address_format: AddressFormat::P2SH,
            },
        );

        encode_eq(b"blkc", Request::Blockchain);

        #[cfg(feature = "simulator")]
        encode_eq(b"XKEY\x01", Request::SimKeypress(0x01));

        encode_eq(b"bagi", Request::BagNumber(None));
        encode_eq(
            b"bagi123abc",
            Request::BagNumber(Some("123abc".to_string())),
        );

        encode_eq(b"hsms", Request::HsmStart(None));
        encode_eq(
            &[
                104, 115, 109, 115, 89, 1, 0, 0, 82, 246, 129, 254, 167, 146, 135, 174, 60, 60,
                152, 151, 192, 167, 53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189, 111,
                107, 237, 24, 89, 172,
            ],
            Request::HsmStart(Some(HsmStartParams {
                length: 345,
                file_sha: BYTES_32.to_owned(),
            })),
        );

        encode_eq(b"hsts", Request::HsmStatus);

        encode_eq(
            b"nwur\x02\x05\x00user1",
            Request::CreateUser {
                auth_mode: AuthMode::HOTP,
                username: Username::new("user1").unwrap(),
                secret: None,
                show_qr: false,
            },
        );
        encode_eq(
            b"nwur\x82\x05\nuser1secret1234",
            Request::CreateUser {
                auth_mode: AuthMode::HOTP,
                username: Username::new("user1").unwrap(),
                secret: Secret::new("secret1234").ok(),
                show_qr: true,
            },
        );

        encode_eq(
            b"rmur\x05user1",
            Request::DeleteUser(Username::new("user1").unwrap()),
        );

        encode_eq(
            b"user\x0c\x00\x00\x00\x05\tuser1token1234",
            Request::UserAuth {
                username: Username::new("user1").unwrap(),
                token: AuthToken::new("token1234").unwrap(),
                totp_time: 12,
            },
        );

        encode_eq(b"gslr", Request::GetStorageLocker);
    }

    #[test]
    fn decode_test() {
        assert!(matches!(
            Response::decode(b"abcd"),
            Err(DecodeError::UnknownFrame(name)) if &name == &[97, 98, 99, 100]));

        assert!(matches!(
            Response::decode(b"fram1234"),
            Err(DecodeError::Framing(text)) if text == "1234".to_string(),
        ));

        assert!(matches!(
            Response::decode(b"err_1234"),
            Err(DecodeError::Protocol(text)) if text == "1234".to_string(),
        ));

        assert!(matches!(Response::decode(b"refu"), Ok(Response::Refused)));

        assert!(matches!(Response::decode(b"busy"), Ok(Response::Busy)));

        assert!(
            matches!(Response::decode(b"biny1234"), Ok(Response::Binary(data)) if &data == &[49, 50, 51, 52])
        );

        assert!(
            matches!(Response::decode(b"int1\xFE\xFF\xFF\xFF"), Ok(Response::Int1(i)) if i == u32::MAX - 1)
        );

        assert!(
            matches!(Response::decode(b"int2\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
            Ok(Response::Int2(i)) if i == u64::MAX - 1)
        );

        assert!(
            matches!(Response::decode(b"int3\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
            Ok(Response::Int3(i)) if i == 79228162514264337593543950334_u128)
        );

        assert!(matches!(
                    Response::decode(&[
            109, 121, 112, 98, 82, 246, 129, 254, 167, 146, 135, 174, 60, 60, 152, 151, 192, 167, 53,
            120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189, 111, 107, 237, 24, 89, 172, 82, 246,
            129, 254, 167, 146, 135, 174, 60, 60, 152, 151, 192, 167, 53, 120, 248, 31, 108, 213, 131,
            160, 94, 44, 58, 189, 111, 107, 237, 24, 89, 172, 64, 226, 1, 0, 111, 0, 0, 0, 116, 112,
            117, 98, 68, 65, 101, 110, 102, 119, 78, 117, 53, 71, 121, 67, 74, 87, 118, 56, 111, 113,
            82, 65, 99, 107, 100, 75, 77, 83, 85, 111, 90, 106, 103, 86, 70, 53, 112, 56, 87, 118, 81,
            119, 72, 81, 101, 88, 106, 68, 104, 65, 72, 109, 71, 114, 80, 97, 52, 97, 52, 121, 50, 70,
            110, 55, 72, 70, 50, 110, 102, 67, 76, 101, 102, 74, 97, 110, 72, 86, 51, 110, 121, 49, 85,
            89, 50, 53, 77, 82, 86, 111, 103, 105, 122, 66, 50, 122, 82, 85, 100, 65, 111, 55, 84, 114,
            57, 88, 65, 106, 109,
        ]),
                    Ok(Response::MyPub {
                                dev_pubkey,
                                xpub_fingerprint,
                                xpub: Some(xpub)
                            }) if &dev_pubkey == BYTES_64 && xpub_fingerprint == [64, 226, 1, 0] &&
                                &xpub == XPUB


                ));

        assert!(matches!(Response::decode(b"ascihello"),
            Ok(Response::Ascii(s)) if &s == "hello"));

        assert!(matches!(
            Response::decode(&[
                115, 109, 114, 120, 34, 0, 0, 0, 49, 81, 50, 84, 87, 72, 69, 51, 71, 77, 100, 66,
                54, 66, 90, 75, 97, 102, 113, 119, 120, 88, 116, 87, 65, 87, 103, 70, 116, 53, 74,
                118, 109, 51, 82, 246, 129, 254, 167, 146, 135, 174, 60, 60, 152, 151, 192, 167,
                53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189, 111, 107, 237, 24, 89, 172,
                82, 246, 129, 254, 167, 146, 135, 174, 60, 60, 152, 151, 192, 167, 53, 120, 248,
                31, 108, 213, 131, 160, 94, 44, 58, 189, 111, 107, 237, 24, 89, 172, 55
            ]),
            // we just added a single 55_u8 to our byte array for easier testing
            Ok(Response::MessageSigned { address, signature })
                if &address.to_string() == "1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3"
                    && &signature[0..64] == BYTES_64 && signature[64] == 55
        ));

        assert!(matches!(
            Response::decode(&[
                115, 116, 114, 120, 89, 1, 0, 0, 82, 246, 129, 254, 167, 146, 135, 174, 60, 60,
                152, 151, 192, 167, 53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58, 189, 111,
                107, 237, 24, 89, 172
            ]),
            Ok(Response::TxSigned { length, sha256 }) if length == 345 && &sha256 == BYTES_32));
    }

    fn encode_eq(a: &'static [u8], b: Request) {
        assert_eq!(a, b.encode().as_slice());
    }

    const BYTES_32: &[u8; 32] = &[
        82, 246, 129, 254, 167, 146, 135, 174, 60, 60, 152, 151, 192, 167, 53, 120, 248, 31, 108,
        213, 131, 160, 94, 44, 58, 189, 111, 107, 237, 24, 89, 172,
    ];

    const BYTES_64: &[u8; 64] = &[
        82, 246, 129, 254, 167, 146, 135, 174, 60, 60, 152, 151, 192, 167, 53, 120, 248, 31, 108,
        213, 131, 160, 94, 44, 58, 189, 111, 107, 237, 24, 89, 172, 82, 246, 129, 254, 167, 146,
        135, 174, 60, 60, 152, 151, 192, 167, 53, 120, 248, 31, 108, 213, 131, 160, 94, 44, 58,
        189, 111, 107, 237, 24, 89, 172,
    ];

    const XPUB: &str = "tpubDAenfwNu5GyCJWv8oqRAckdKMSUoZjgVF5p8WvQwHQeXjDhAHmGrPa4a4y2Fn7HF2nfCLefJanHV3ny1UY25MRVogizB2zRUdAo7Tr9XAjm";
}
