//! # Coldcard interface library in Rust.
//!
//! This library provides interfacing functionality for the Coldcard hardware wallet.
//! It automatically sets up an encrypted communication channel using ECDH
//! that cannot be turned off, so MITM mitigation is possible out of the box
//! using the `check_mitm` method.
//!
//! It does not validate that a particular function is available on a particular
//! Coldcard (due to firmware differences), so that is left to the user to explore.
//!
//! ```no_run
//! use coldcard::protocol;
//!
//! # fn main() -> Result<(), coldcard::Error> {
//! // create an API instance
//! let mut api = coldcard::Api::new()?;
//!
//! // detect all connected Coldcards
//! let serials = api.detect()?;
//!
//! // get the first serial and open it
//! let first = serials.into_iter().next().unwrap();
//! let (mut cc, master_xpub) = api.open(first, None).unwrap();
//!
//! // set a passphrase
//! cc.set_passphrase(protocol::Passphrase::new("secret")?)?;
//!
//! // after the user confirms
//! let xpub = cc.get_passphrase_done()?;
//!
//! if let Some(xpub) = xpub {
//!    println!("The new XPUB is: {}", xpub);
//! }
//!
//! // secure logout
//! cc.logout()?;
//!
//! # Ok(())
//! # }
//! ```
pub mod constants;
pub mod firmware;
pub mod protocol;
pub mod util;

use std::sync::OnceLock;

use protocol::{DerivationPath, Request, Response, Username};

pub const COINKITE_VID: u16 = 0xd13e;
pub const CKCC_PID: u16 = 0xcc10;

static INIT: OnceLock<()> = OnceLock::new();

/// API for interacting with Coldcard devices. Only one instance can exist per program lifetime.
pub struct Api(hidapi::HidApi);

impl Api {
    /// Creates a new API for interacting with Coldcard devices.
    ///
    /// It is possible to have only one instance. Creating more than one will return an error.
    pub fn new() -> Result<Self, Error> {
        match INIT.set(()) {
            Ok(_) => Ok(Self(hidapi::HidApi::new()?)),
            Err(_) => Err(Error::ApiAlreadyInitialized),
        }
    }

    /// Detects connected Coldcard devices and returns a vector of their serial numbers.
    ///
    /// **If a Coldcard isn't being detected on Linux, check the udev instructions.**
    pub fn detect(&mut self) -> Result<Vec<SerialNumber>, Error> {
        self.0.refresh_devices()?;

        let serials = self
            .0
            .device_list()
            .map(|dev| {
                #[cfg(feature = "log")]
                log::trace!(
                    "Detected HID device: vid={} pid={} vendor={} sn={}",
                    dev.vendor_id(),
                    dev.product_id(),
                    dev.manufacturer_string().unwrap_or_default(),
                    dev.serial_number().unwrap_or_default()
                );
                dev
            })
            .filter(|dev| dev.vendor_id() == COINKITE_VID && dev.product_id() == CKCC_PID)
            .map(|cc| SerialNumber(cc.serial_number().unwrap_or_default().to_owned()))
            .collect();

        Ok(serials)
    }

    /// Opens a Coldcard with a particular serial number and optionally some options.
    /// If no serial number is known, use the `Api::detect()` method to detect connected
    /// Coldcard devices. Returns an optional `XpubInfo` in case the device is
    /// already initialized with a secret.
    pub fn open(
        &self,
        sn: impl AsRef<str>,
        opts: Option<Options>,
    ) -> Result<(Coldcard, Option<XpubInfo>), Error> {
        Coldcard::open(self, sn, opts)
    }
}

impl AsRef<hidapi::HidApi> for Api {
    fn as_ref(&self) -> &hidapi::HidApi {
        &self.0
    }
}

/// Specifies various options that a Coldcard can be opened with.
#[derive(Debug)]
pub struct Options {
    pub encrypt_version: u32,
    pub resync_on_open: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            encrypt_version: 1,
            resync_on_open: false,
        }
    }
}

/// Represents a particular Coldcard serial number.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SerialNumber(String);

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
    /// Opens a Coldcard with a particular serial number and optionally some options.
    /// If no serial number is known, use the `Api::detect()` method to detect connected
    /// Coldcard devices. Returns an optional `XpubInfo` in case the device is
    /// already initialized with a secret.
    pub fn open(
        api: impl AsRef<hidapi::HidApi>,
        sn: impl AsRef<str>,
        opts: Option<Options>,
    ) -> Result<(Self, Option<XpubInfo>), Error> {
        let mut cc = api
            .as_ref()
            .open_serial(COINKITE_VID, CKCC_PID, sn.as_ref())?;

        #[cfg(feature = "log")]
        log::info!("opened SN {} with opts: {:?}", sn.as_ref(), opts);
        let opts = opts.unwrap_or_default();

        let mut read_buf = [0_u8; 64];
        let mut send_buf = [0_u8; 2 + constants::CHUNK_SIZE];

        if opts.resync_on_open {
            resync(&mut cc, &mut read_buf)?;
        }

        let mut rng = rand::rngs::ThreadRng::default();
        let our_sk = k256::SecretKey::random(&mut rng);
        let our_pk = our_sk.public_key();

        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let encrypt_start = Request::EncryptStart {
            device_pubkey: our_pk.to_encoded_point(false).as_bytes()[1..]
                .try_into()
                .map_err(|_| k256::elliptic_curve::Error)?,
            version: Some(opts.encrypt_version),
        };

        send(encrypt_start, &mut cc, None, &mut send_buf)?;
        let (cc_pk, xpub_fingerprint, xpub) = recv(&mut cc, None, &mut read_buf)?.into_my_pub()?;

        // this is because the Coldcard returns a 64 byte pk (no sec1 0x04 prefix)
        let mut prefixed_cc_pk = Vec::with_capacity(65);
        prefixed_cc_pk.push(0x04);
        prefixed_cc_pk.extend_from_slice(&cc_pk);

        let cc_pk = k256::PublicKey::from_sec1_bytes(&prefixed_cc_pk)?;
        let session_key = session_key(our_sk, cc_pk)?;

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
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::Signature;

        let pk = util::decode_xpub(expected_xpub).ok_or(Error::NoSecretOnDevice)?;
        let verifying_key = k256::ecdsa::VerifyingKey::from(pk);

        let (r, s): ([u8; 32], [u8; 32]) = match self.send(Request::CheckMitm)? {
            Response::Binary(sig) if sig.len() == 65 => {
                let (r, s) = sig[1..].split_at(32);
                Ok((r.try_into().unwrap(), s.try_into().unwrap()))
            }
            _ => Err(Error::NoSecretOnDevice),
        }?;

        let sig = Signature::from_scalars(r, s).map_err(|_| k256::elliptic_curve::Error)?;

        let verified = verifying_key.verify_prehash(&self.session_key, &sig);

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
                return Err(Error::TransmissionFailed);
            }
        }

        let uploaded_checksum = self.send(Request::Sha256)?.into_binary()?;
        if checksum != uploaded_checksum.as_slice() {
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
            if here.is_empty() {
                return Err(Error::TransmissionFailed);
            }
        }

        let actual_checksum = hash_engine.finalize();
        if actual_checksum == checksum {
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

        Ok((!secret.is_empty()).then_some(secret))
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
            response => Err(response.into()),
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
                file_sha: util::sha256(policy),
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

    /// Enroll miniscript file.
    pub fn miniscript_enroll(&mut self, descriptor: &[u8]) -> Result<(), Error> {
        let file_sha = self.upload(descriptor)?;

        self.send(Request::MiniscriptEnroll {
            length: descriptor.len() as u32,
            file_sha,
        })?
        .into_ok()
        .map_err(Error::from)
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
        let file_sha = self.upload(psbt)?;

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

        use rand::RngCore;
        let mut rng = rand::thread_rng();

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

impl std::fmt::Debug for Coldcard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coldcard").field("sn", &self.sn).finish()
    }
}

/// Computes a shared session key using ECDH.
fn session_key(sk: k256::SecretKey, pk: k256::PublicKey) -> Result<[u8; 32], Error> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let tweaked_pk = *pk.as_affine() * *sk.to_nonzero_scalar();
    let tweaked_pk = k256::PublicKey::from_affine(tweaked_pk.to_affine())?;
    let pt = tweaked_pk.to_encoded_point(false);

    Ok(util::sha256(&pt.as_bytes()[1..]))
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

    #[cfg(feature = "log")]
    if let Ok(cmd) = std::str::from_utf8(&data[..4]) {
        log::debug!(
            "sending: command={}, encrypt={}, req_size={}",
            cmd,
            encrypt,
            data.len()
        );
    }

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

        #[cfg(feature = "log")]
        log::trace!("writing packet...");
        cc.write(send_buf)?;

        #[cfg(feature = "log")]
        log::debug!("packet #{} written out", i);
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
        #[cfg(feature = "log")]
        log::trace!("reading packet...");
        let read = cc.read(read_buf)?;

        if read != read_buf.len() {
            return Err(Error::TransmissionFailed);
        }
        let flag = read_buf[0];
        let is_last = flag & 0x80 != 0;
        let is_encrypted = flag & 0x40 != 0;
        let length = (flag & 0x3f) as usize;

        #[cfg(feature = "log")]
        log::debug!("packet read ({} bytes)", length);

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
            return Err(Error::EncryptionNotSetUp);
        }
    }

    #[cfg(feature = "log")]
    {
        match std::str::from_utf8(&data[..4]) {
            Ok(cmd) => {
                log::debug!(
                    "received: cmd={}, encrypt={}, resp_size={}",
                    cmd,
                    is_encrypted,
                    data.len()
                )
            }
            Err(_) => log::warn!(
                "received: unknown frame, encrypt={}, resp_size{}",
                is_encrypted,
                data.len()
            ),
        }
    }

    Response::decode(data).map_err(Error::Decoding)
}

/// Resyncs a Coldcard. Can block for short periods of time.
fn resync(cc: &mut hidapi::HidDevice, read_buf: &mut [u8; 64]) -> Result<(), Error> {
    #[cfg(feature = "log")]
    log::debug!("resyncing");
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
    ApiAlreadyInitialized,
    UnexpectedResponse(Response),
    Encoding(protocol::EncodeError),
    Decoding(protocol::DecodeError),
    DerivationPath(protocol::derivation_path::Error),
    Hid(hidapi::HidError),
    EncryptionNotSetUp,
    Secp256k1,
    NoSecretOnDevice,
    ChecksumMismatch,
    TransmissionFailed,
    TestFailureWithLength(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
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

impl From<protocol::derivation_path::Error> for Error {
    fn from(error: protocol::derivation_path::Error) -> Self {
        Self::DerivationPath(error)
    }
}

impl From<hidapi::HidError> for Error {
    fn from(error: hidapi::HidError) -> Self {
        Error::Hid(error)
    }
}

impl From<k256::elliptic_curve::Error> for Error {
    fn from(_: k256::elliptic_curve::Error) -> Self {
        Error::Secp256k1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_test() {
        // Test vectors generated using Python's ECDSA library.

        let sk = k256::SecretKey::from_slice(&[
            54, 87, 69, 21, 237, 128, 12, 240, 76, 202, 164, 71, 187, 45, 83, 164, 166, 220, 223,
            141, 45, 194, 122, 194, 238, 254, 252, 128, 11, 241, 248, 173,
        ])
        .unwrap();

        let pk = sk.public_key();

        let key = session_key(sk, pk).unwrap();

        assert!(matches!(
            key,
            [
                97, 10, 203, 217, 188, 148, 215, 133, 15, 230, 124, 53, 141, 69, 124, 66, 67, 92,
                157, 16, 21, 21, 229, 234, 131, 191, 156, 46, 47, 231, 92, 40
            ]
        ));
    }
}
