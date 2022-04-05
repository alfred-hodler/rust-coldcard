pub mod constants;
pub mod firmware;
pub mod protocol;
pub mod util;

use hidapi::HidApi;
use protocol::{DerivationPath, Request, Response, Username};

const COINKITE_VID: u16 = 0xd13e;
const CKCC_PID: u16 = 0xcc10;

/// Detects connected Coldcard devices and returns a vector of their serial numbers.
pub fn detect() -> Result<Vec<SerialNumber>, Error> {
    let serials: Vec<_> = hidapi::HidApi::new()?
        .device_list()
        .filter(|dev| dev.vendor_id() == COINKITE_VID && dev.product_id() == CKCC_PID)
        .map(|cc| SerialNumber(cc.serial_number().unwrap_or_default().to_owned()))
        .collect();

    Ok(serials)
}

/// Represents a particular Coldcard serial number.
pub struct SerialNumber(String);

impl SerialNumber {
    /// Opens a Coldcard with a particular serial number. Optionally with
    /// an expected xpub for anti-MITM.
    pub fn open(&self) -> Result<(Coldcard, Option<XpubInfo>), Error> {
        Coldcard::open(&self.0)
    }

    /// The string value of this serial number.
    pub fn value(&self) -> &str {
        self.as_ref()
    }
}

impl AsRef<str> for SerialNumber {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// B58 encoded xpub and its fingerprint.
#[derive(Debug)]
pub struct XpubInfo {
    pub xpub: String,
    pub fingerprint: [u8; 4],
}

/// Signed message (binary) and the address that signed it.
#[derive(Debug)]
pub struct SignedMessage {
    pub signature: [u8; 65],
    pub address: String,
}

/// Backup bytes and their checksum as calculated by Coldcard.
#[derive(Debug)]
pub struct Backup {
    pub data: Vec<u8>,
    pub sha256: [u8; 32],
}

/// Signing mode for PSBT.
#[derive(Debug)]
#[repr(u32)]
pub enum SignMode {
    Visualize = constants::STXN_VISUALIZE,
    VisualizeSigned = constants::STXN_VISUALIZE | constants::STXN_SIGNED,
    Finalize = constants::STXN_FINALIZE,
}

/// Connected and initialized Coldcard device ready for use.
pub struct Coldcard {
    cc: hidapi::HidDevice,
    session_key: [u8; 32],
    encrypt: aes_ctr::Aes256Ctr,
    decrypt: aes_ctr::Aes256Ctr,
    sn: String,

    // performance helpers
    read_buf: [u8; 64],
    send_buf: [u8; 2 + constants::CHUNK_SIZE],
}

impl Coldcard {
    /// Opens a Coldcard with a particular serial number. If no serial number is known,
    /// use the `SerialNumber` type to detect connected Coldcard devices. Also returns
    /// an optional `XpubInfo` in case the device is already initialized with a secret.
    pub fn open(sn: impl AsRef<str>) -> Result<(Self, Option<XpubInfo>), Error> {
        let mut cc = HidApi::new()?.open_serial(COINKITE_VID, CKCC_PID, sn.as_ref())?;

        let mut read_buf = [0_u8; 64];
        let mut send_buf = [0_u8; 2 + constants::CHUNK_SIZE];

        resync(&mut cc, &mut read_buf)?;

        let secp = secp256k1::Secp256k1::new();
        let mut rng = secp256k1::rand::rngs::OsRng::new()?;
        let our_sk = secp256k1::SecretKey::new(&mut rng);
        let our_pk = secp256k1::PublicKey::from_secret_key(&secp, &our_sk);

        let encrypt_start = Request::EncryptStart {
            device_pubkey: our_pk.serialize_uncompressed()[1..].try_into().unwrap(),
            version: None,
        };

        send(encrypt_start, &mut cc, None, &mut send_buf)?;
        let (cc_pk, xpub_fingerprint, xpub) = recv(&mut cc, None, &mut read_buf)?.into_my_pub()?;

        // this is because the Coldcard returns a 64 byte pk (no 0x04 prefix)
        let mut prefixed_cc_pk = Vec::with_capacity(65);
        prefixed_cc_pk.push(0x04);
        prefixed_cc_pk.extend_from_slice(&cc_pk);

        let cc_pk = secp256k1::PublicKey::from_slice(&prefixed_cc_pk)?;
        let session_key = session_key(&our_sk, &cc_pk)?;

        let (encrypt, decrypt) = {
            use aes_ctr::cipher::{generic_array::GenericArray, stream::NewStreamCipher};
            use aes_ctr::Aes256Ctr;

            let key = GenericArray::from_slice(&session_key);
            let nonce = GenericArray::from_slice(&[0_u8; 16]);

            (Aes256Ctr::new(key, nonce), Aes256Ctr::new(key, nonce))
        };

        cc.set_blocking_mode(true)?;

        let cc = Self {
            cc,
            session_key,
            encrypt,
            decrypt,
            read_buf,
            send_buf,
            sn: sn.as_ref().to_owned(),
        };

        Ok((
            cc,
            xpub.map(|xpub| XpubInfo {
                xpub,
                fingerprint: xpub_fingerprint,
            }),
        ))
    }

    /// Sends a request and immediately reads a response.
    pub fn send(&mut self, request: Request) -> Result<Response, Error> {
        send(
            request,
            &mut self.cc,
            Some(&mut self.encrypt),
            &mut self.send_buf,
        )?;
        recv(&mut self.cc, Some(&mut self.decrypt), &mut self.read_buf)
    }

    /// Checks if the communication line is undergoing a MITM attack.
    /// Returns `Ok(true)` if MITM is in progress or `Ok(false)` if not.
    pub fn check_mitm(&mut self, expected_xpub: &str) -> Result<bool, Error> {
        use secp256k1::{ecdsa::Signature, Message};

        let pk = util::decode_xpub(&expected_xpub).ok_or(Error::NoSecretOnDevice)?;
        let msg = Message::from_slice(&self.session_key)?;

        let sig = match self.send(Request::CheckMitm)? {
            Response::Binary(sig) if sig.len() == 65 => Ok(Signature::from_compact(&sig[1..])?),
            _ => Err(Error::NoSecretOnDevice),
        }?;

        let verified = secp256k1::Secp256k1::verification_only().verify_ecdsa(&msg, &sig, &pk);

        Ok(verified.is_err())
    }

    /// Uploads a file and verifies the checksum. Returns the checksum
    /// calculated by the device. Fails on checksum verification failure.
    pub fn upload(&mut self, data: &[u8]) -> Result<[u8; 32], Error> {
        let checksum = util::sha256(data);

        for (i, blk) in data.chunks(constants::MAX_BLK_LEN).enumerate() {
            let blk_offset = (i * constants::MAX_BLK_LEN) as u32;
            let pos = self
                .send(Request::Upload {
                    offset: blk_offset,
                    total_size: data.len() as u32,
                    data: protocol::Upload::new(blk)?,
                })?
                .into_int1()?;

            if pos != blk_offset {
                return Err(Error::UploadFailed);
            }
        }

        let uploaded_checksum = self.send(Request::Sha256)?.into_binary()?;
        if !(&checksum == uploaded_checksum.as_slice()) {
            return Err(Error::ChecksumMismatch);
        }

        Ok(uploaded_checksum
            .try_into()
            .expect("Did not get a 32 byte checksum back; Coldcard error"))
    }

    /// Downloads a single file with a known checksum. Fails on checksum
    /// verification failure.
    pub fn download(
        &mut self,
        length: u32,
        checksum: &[u8],
        file_number: protocol::FileNo,
    ) -> Result<Vec<u8>, Error> {
        let mut data = Vec::with_capacity(length as usize);

        let mut hash_engine = util::Sha256Engine::default();

        let mut pos = 0;
        while pos < length {
            let blk_len = constants::MAX_BLK_LEN.min((length - pos) as usize) as u32;
            let here = self
                .send(Request::Download {
                    offset: pos as u32,
                    length: blk_len,
                    file_number,
                })?
                .into_binary()?;

            data.extend_from_slice(here.as_slice());
            hash_engine.update(here.as_slice());
            pos += here.len() as u32;
            if here.len() == 0 {
                return Err(Error::DownloadFailed);
            }
        }

        let actual_checksum = hash_engine.finalize();
        if &actual_checksum == checksum {
            Ok(data)
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Resyncs the Coldcard by sending a magic packet and discarding
    /// data until it is ready for use again. Normally no need to use this.
    pub fn resync(&mut self) -> Result<(), Error> {
        resync(&mut self.cc, &mut self.read_buf)
    }

    // CONVENIENCE FUNCTIONS FOLLOW.
    // All these can also be achieved by using the send(Request::*) notation

    /// Gets an address given a derivation path and address format.
    pub fn address(
        &mut self,
        subpath: protocol::DerivationPath,
        addr_fmt: protocol::AddressFormat,
    ) -> Result<String, Error> {
        self.send(Request::ShowAddress { subpath, addr_fmt })?
            .into_ascii()
            .map_err(Error::from)
    }

    /// Gets the bag number the Coldcard arrived in.
    pub fn bag_number(&mut self) -> Result<String, Error> {
        self.send(Request::BagNumber(None))?
            .into_ascii()
            .map_err(Error::from)
    }

    /// Gets the name of the blockchain the Colcard is set to operate on.
    pub fn blockchain(&mut self) -> Result<String, Error> {
        self.send(Request::Blockchain)?
            .into_ascii()
            .map_err(Error::from)
    }

    /// Creates a new username on the Coldcard. If a QR code is requested, the generated
    /// secret is displayed only on the device. Otherwise it is returned in the `Ok(...)` variant.
    pub fn create_username(
        &mut self,
        username: Username,
        auth_mode: protocol::AuthMode,
        show_qr: bool,
    ) -> Result<Option<String>, Error> {
        let secret = self
            .send(Request::CreateUser {
                username,
                auth_mode,
                secret: None,
                show_qr,
            })?
            .into_ascii()?;

        Ok((!secret.is_empty()).then(|| secret))
    }

    /// Deletes a username, if one exists on the Coldcard. Returns `Ok(())` even
    /// if one did not exist.
    pub fn delete_username(&mut self, username: Username) -> Result<(), Error> {
        self.send(Request::DeleteUser(username))?
            .into_ok()
            .map_err(Error::from)
    }

    /// Gets a backup from the Coldcard, if one was previously initiated. If the result is
    /// `Ok(None)`, it can mean that the user has not approved yet or the backup has not completed.
    pub fn get_backup(&mut self) -> Result<Option<Backup>, Error> {
        let backup = self.send(Request::GetBackupFile)?;
        match backup {
            Response::Ok => Ok(None),
            Response::TxSigned { length, sha256 } => {
                let data = self.download(length, &sha256, protocol::FileNo::Zero)?;
                Ok(Some(Backup { data, sha256 }))
            }
            response => Err(response.into()),
        }
    }

    /// Gets the new xpub from the Coldcard, upon setting a passphrase. If the result is
    /// `Ok(None)`, it can mean that the user has not approved yet.
    pub fn get_passphrase_done(&mut self) -> Result<Option<String>, Error> {
        let xpub = self.send(Request::GetPassphraseDone)?;
        match xpub {
            Response::Ok => Ok(None),
            Response::Ascii(xpub) => Ok(Some(xpub)),
            response => Err(response.into()),
        }
    }

    /// Gets a signed message from the Coldcard, if any. If the result is `Ok(None)`, it
    /// can mean that the user has not approved yet.
    pub fn get_signed_message(&mut self) -> Result<Option<SignedMessage>, Error> {
        let sig = self.send(Request::GetSignedMessage)?;
        match sig {
            Response::Ok => Ok(None),
            Response::MessageSigned { address, signature } => {
                Ok(Some(SignedMessage { address, signature }))
            }
            response => Err(Error::UnexpectedResponse(response)),
        }
    }

    /// Gets a signed transaction from the Coldcard, if one was previously created. If the result is
    /// `Ok(None)`, it can mean that the user has not approved yet or the signing has not completed.
    pub fn get_signed_tx(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let tx = self.send(Request::GetSignedTransaction)?;
        match tx {
            Response::Ok => Ok(None),
            Response::TxSigned { length, sha256 } => {
                let data = self.download(length, &sha256, protocol::FileNo::One)?;
                Ok(Some(data))
            }
            response => Err(response.into()),
        }
    }

    /// Starts the HSM mode given a policy. If the policy is `None`,
    /// starts the existing policy already on the device.
    pub fn hsm_start(&mut self, policy: Option<&[u8]>) -> Result<(), Error> {
        if let Some(policy) = policy {
            self.upload(policy)?;
            self.send(Request::HsmStart(Some(protocol::HsmStartParams {
                file_sha: util::sha256(&policy),
                length: policy.len() as u32,
            })))?
            .into_ok()
        } else {
            self.send(Request::HsmStart(None))?.into_ok()
        }
        .map_err(Error::from)
    }

    /// Gets the HSM policy file in the JSON format.
    pub fn hsm_policy(&mut self) -> Result<String, Error> {
        self.send(Request::HsmStatus)?
            .into_ascii()
            .map_err(Error::from)
    }

    /// Gets the value in the storage locker (HSM use).
    pub fn locker(&mut self) -> Result<Vec<u8>, Error> {
        self.send(Request::GetStorageLocker)?
            .into_binary()
            .map_err(Error::from)
    }

    /// Securely logs out of the Coldcard. Requires a power cycle to use again.
    pub fn logout(mut self) -> Result<(), Error> {
        self.send(Request::Logout)?.into_ok().map_err(Error::from)
    }

    /// Reboots the Coldcard.
    pub fn reboot(mut self) -> Result<(), Error> {
        self.send(Request::Reboot)?.into_ok().map_err(Error::from)
    }

    /// Returns the serial number of this Coldcard.
    pub fn serial_number(&self) -> &str {
        &self.sn
    }

    /// Sets a BIP39 passphrase. Provide an empty passphrase to remove. This does
    /// not immediately return the new xpub, use `get_passphrase_done` for that.
    pub fn set_passphrase(&mut self, passphrase: protocol::Passphrase) -> Result<(), Error> {
        self.send(Request::Bip39Passphrase(passphrase))?
            .into_ok()
            .map_err(Error::from)
    }
    /// Initiates message signing and causes the Coldcard to prompt the user to confirm.
    /// This does not immediately return a signature, use `get_signed_message` for that.
    pub fn sign_message(
        &mut self,
        raw_msg: protocol::Message,
        subpath: Option<DerivationPath>,
        addr_fmt: protocol::AddressFormat,
    ) -> Result<(), Error> {
        let request = Request::SignMessage {
            raw_msg,
            subpath,
            addr_fmt,
        };

        self.send(request)?.into_ok().map_err(Error::from)
    }

    /// Initiates PSBT signing and causes the Coldcard to prompt the user to confirm.
    /// This does not immediately return a signed tx, use `get_signed_tx` for that.
    pub fn sign_psbt(&mut self, psbt: &[u8], sign_mode: SignMode) -> Result<(), Error> {
        let file_sha = self.upload(&psbt)?;

        self.send(Request::SignTransaction {
            length: psbt.len() as u32,
            file_sha,
            flags: Some(sign_mode as u32),
        })?
        .into_ok()
        .map_err(Error::from)
    }

    /// Initiates a backup and causes the Coldcard to prompt the user to confirm.
    /// This does not immediately return a backup, use `get_backup` for that.
    pub fn start_backup(&mut self) -> Result<(), Error> {
        self.send(Request::StartBackup)?
            .into_ok()
            .map_err(Error::from)
    }

    /// Tests the Coldcard and the USB connection by sending predefined data packets.
    pub fn test(&mut self) -> Result<(), Error> {
        let lengths: Vec<usize> = (55..66)
            .into_iter()
            .chain(1013..1024)
            .chain(constants::MAX_MSG_LEN - 10..constants::MAX_MSG_LEN - 4)
            .collect();

        use secp256k1::rand::RngCore;
        let mut rng = secp256k1::rand::thread_rng();

        for len in lengths {
            let mut ping = Vec::new();
            rng.fill_bytes(&mut ping);
            let pong = self.send(Request::Ping(ping.clone()))?.into_binary()?;
            if ping != pong {
                return Err(Error::TestFailureWithLength(len));
            }
        }

        Ok(())
    }

    /// Upgrades the firmware on the Coldcard. It does not reboot automatically.
    pub fn upgrade(&mut self, firmware: firmware::Firmware) -> Result<(), Error> {
        self.upload(&firmware.0)?;
        Ok(())
    }

    /// Authenticates a user (for HSM).
    pub fn user_auth(
        &mut self,
        username: Username,
        token: protocol::AuthToken,
        totp_time: u32,
    ) -> Result<(), Error> {
        let response = self.send(Request::UserAuth {
            username,
            token,
            totp_time,
        })?;

        match response {
            Response::Ascii(s) if s.is_empty() => Ok(()),
            r => Err(r.into()),
        }
    }

    /// Gets the static version string from the Coldcard.
    pub fn version(&mut self) -> Result<String, Error> {
        self.send(Request::Version)?
            .into_ascii()
            .map_err(Error::from)
    }

    /// Gets a B58 encoded xpub at some derivation path. Master level if `None`.
    pub fn xpub(&mut self, path: Option<DerivationPath>) -> Result<String, Error> {
        self.send(Request::GetXPub(path))?
            .into_ascii()
            .map_err(Error::from)
    }
}

/// Computes a shared session key using ECDH.
fn session_key(sk: &secp256k1::SecretKey, pk: &secp256k1::PublicKey) -> Result<[u8; 32], Error> {
    let secp = secp256k1::Secp256k1::new();

    let mut pt = pk.clone();
    pt.mul_assign(&secp, &sk.secret_bytes())?;

    let hash = util::sha256(&pt.serialize_uncompressed()[1..]);

    Ok(hash)
}

/// Sends a request to a Coldcard.
fn send(
    request: Request,
    cc: &mut hidapi::HidDevice,
    cipher: Option<&mut aes_ctr::Aes256Ctr>,
    send_buf: &mut [u8; 2 + constants::CHUNK_SIZE],
) -> Result<(), Error> {
    let mut data = request.encode();

    let encrypt = cipher.is_some();
    if let Some(cipher) = cipher {
        use aes_ctr::cipher::stream::SyncStreamCipher;
        cipher.apply_keystream(&mut data);
    }

    let chunks = data.chunks(constants::CHUNK_SIZE);
    let n_chunks = chunks.len();
    for (i, chunk) in chunks.enumerate() {
        let is_last = i == n_chunks - 1;
        let byte_1 = (chunk.len() as u8)
            | if is_last {
                0x80 | if encrypt { 0x40 } else { 0x00 }
            } else {
                0x00
            };

        send_buf[0] = 0;
        send_buf[1] = byte_1;
        send_buf[2..2 + chunk.len()].copy_from_slice(chunk);

        cc.write(send_buf)?;
    }

    Ok(())
}

/// Reads a response from a Coldcard.
fn recv(
    cc: &mut hidapi::HidDevice,
    cipher: Option<&mut aes_ctr::Aes256Ctr>,
    read_buf: &mut [u8; 64],
) -> Result<Response, Error> {
    let mut data: Vec<u8> = Vec::new();
    let (data, is_encrypted) = loop {
        let read = cc.read(read_buf)?;
        if read != read_buf.len() {
            return Err(Error::ReadBlockTooShort);
        }
        let flag = read_buf[0];
        let is_last = flag & 0x80 != 0;
        let is_encrypted = flag & 0x40 != 0;
        let length = (flag & 0x3f) as usize;

        // this is a small optimization to avoid vector allocation
        // when a response is sufficiently small to fit the buffer
        if data.is_empty() && is_last {
            break (&mut read_buf[1..1 + length], is_encrypted);
        } else {
            data.extend(&read_buf[1..1 + length]);
            if is_last {
                break (&mut data, is_encrypted);
            }
        }
    };

    if is_encrypted {
        if let Some(cipher) = cipher {
            use aes_ctr::cipher::stream::SyncStreamCipher;
            cipher.apply_keystream(data);
        } else {
            return Err(CryptoError::NotSetUp.into());
        }
    }

    Response::decode(&data).map_err(Error::Decoding)
}

/// Resyncs a Coldcard. Can block for short periods of time.
fn resync(cc: &mut hidapi::HidDevice, read_buf: &mut [u8; 64]) -> Result<(), Error> {
    fn read_junk(
        cc: &mut hidapi::HidDevice,
        read_buf: &mut [u8; 64],
    ) -> Result<(), hidapi::HidError> {
        loop {
            let read = cc.read_timeout(read_buf, 100)?;
            if read == 0 {
                break;
            }
        }
        Ok(())
    }

    read_junk(cc, read_buf)?;

    let mut special_packet = vec![0xff_u8, 65];
    special_packet[0] = 0x00;
    special_packet[1] = 0x80;
    cc.write(&special_packet)?;

    read_junk(cc, read_buf)?;

    Ok(())
}

/// Any type of error that can occur while a Coldcard is being used.
#[derive(Debug)]
pub enum Error {
    ReadBlockTooShort,
    UnexpectedResponse(Response),
    Encoding(protocol::EncodeError),
    Decoding(protocol::DecodeError),
    Hid(hidapi::HidError),
    Encryption(CryptoError),
    NoSecretOnDevice,
    ChecksumMismatch,
    UploadFailed,
    DownloadFailed,
    NoColdcard,
    TestFailureWithLength(usize),
    UserTimeout,
}

impl From<Response> for Error {
    fn from(error: Response) -> Self {
        Self::UnexpectedResponse(error)
    }
}

impl From<protocol::EncodeError> for Error {
    fn from(error: protocol::EncodeError) -> Self {
        Self::Encoding(error)
    }
}

impl From<hidapi::HidError> for Error {
    fn from(error: hidapi::HidError) -> Self {
        Error::Hid(error)
    }
}

impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Encryption(error)
    }
}

/// Errors related to cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    Rng(secp256k1::rand::Error),
    Secp256k1(secp256k1::Error),
    NotSetUp,
}

impl From<secp256k1::rand::Error> for Error {
    fn from(error: secp256k1::rand::Error) -> Self {
        CryptoError::Rng(error).into()
    }
}

impl From<secp256k1::Error> for Error {
    fn from(error: secp256k1::Error) -> Self {
        CryptoError::Secp256k1(error).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_test() {
        // Test vectors generated using Python's ECDSA library.
        let secp = secp256k1::Secp256k1::new();

        let sk = secp256k1::SecretKey::from_slice(&[
            54, 87, 69, 21, 237, 128, 12, 240, 76, 202, 164, 71, 187, 45, 83, 164, 166, 220, 223,
            141, 45, 194, 122, 194, 238, 254, 252, 128, 11, 241, 248, 173,
        ])
        .unwrap();

        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let key = session_key(&sk, &pk);

        assert!(matches!(
            key,
            Ok([
                97, 10, 203, 217, 188, 148, 215, 133, 15, 230, 124, 53, 141, 69, 124, 66, 67, 92,
                157, 16, 21, 21, 229, 234, 131, 191, 156, 46, 47, 231, 92, 40
            ])
        ));
    }
}
