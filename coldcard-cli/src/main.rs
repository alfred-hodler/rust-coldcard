#![allow(clippy::result_large_err)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use coldcard::protocol::{self, derivation_path, Response};
use coldcard::{firmware, Backup, Options, SignedMessage};
use coldcard::{util, XpubInfo};

use clap::Parser;

mod fw_upgrade;
mod xpub_version;

#[derive(clap::Parser)]
#[clap(author, version, about)]
#[clap(propagate_version = true)]
struct Cli {
    /// The main command to execute
    #[clap(subcommand)]
    command: Command,

    /// The Coldcard serial number to operate on (default: first one found)
    #[clap(long)]
    serial: Option<String>,

    /// Perform a MITM check against an xpub
    #[clap(long)]
    xpub: Option<String>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Show the address for a derivation path
    Address {
        path: String,
        #[clap(arg_enum)]
        format: AddressFormat,
    },

    /// Authenticate a specific user using a 6-digit token (for HSM)
    AuthToken {
        /// The username to authenticate with
        username: String,
        /// The 6-digit token to authenticate with. Will be prompted if missing.
        token: Option<String>,
    },

    /// Initiate the backup process and create an encrypted 7z file
    Backup {
        /// The path to the file where the backup should be saved,
        /// including the filename
        path: PathBuf,
    },

    /// Show the bag number the Coldcard arrived in
    Bag,

    /// Show the configured blockchain
    Chain,

    /// Delete a specific HSM user
    DeleteUser { username: String },

    /// Show the current HSM policy
    Hsm,

    /// Starts the HSM mode (with a specific policy)
    HsmStart {
        /// The path to the new policy file. If missing,
        /// the existing policy is started.
        path: Option<PathBuf>,
    },

    /// Installs the udev file required to detect Coldcards on Linux.
    #[cfg(target_os = "linux")]
    InstallUdevRules,

    /// List the serial numbers of connected Coldcards
    List,

    /// Generate a 6-digit code for PSBT signing in HSM mode
    LocalConf {
        /// The path to the PSBT file
        psbt: PathBuf,
        /// The next code to use (default: get from device)
        next_code: Option<String>,
    },

    /// Get the hex contents of the storage locker (HSM mode only).
    Locker {
        /// Encode the output as UTF-8. This can fail if not UTF-8.
        #[clap(long)]
        utf8: bool,
    },

    /// Securely log out of the Coldcard
    Logout,

    /// Sign a text message with a specific derivation path
    Message {
        /// The message to sign
        message: String,
        /// The address format
        #[clap(arg_enum)]
        address_format: AddressFormat,
        /// The optional derivation path to use (default: master)
        path: Option<String>,
        /// Wrap the signature in ASCII armor
        #[clap(long)]
        armor: bool,
    },

    /// Set a BIP39 passphrase.
    Passphrase {
        /// Read the passphrase from stdin instead of console. Leading and trailing
        /// newlines and whitespaces are trimmed off.
        #[clap(long)]
        stdin: bool,
    },

    /// Show the pubkey for a derivation path
    Pubkey { path: String },

    /// Reboot the Coldcard
    Reboot,

    /// Sign a spending PSBT transaction
    Sign {
        /// The path to the PSBT file to sign
        psbt_in: PathBuf,
        /// The signing mode to use
        #[clap(arg_enum)]
        mode: SignMode,
        /// Output in base64 (default: hex)
        #[clap(long)]
        base64: bool,
        /// The optional path where to write out the signed tx (default: stdout)
        psbt_out: Option<PathBuf>,
    },

    /// Test USB connection
    Test,

    /// Download and upgrade to the latest firmware, or upgrade from file.
    Upgrade {
        /// The path to the firmware file. If none, runs in the interactive (auto download) mode
        /// trying to find the best match on the official website.
        path: Option<PathBuf>,
    },

    /// Create a new HSM user. The secret is generated on the device
    User {
        /// The username to create
        username: String,
        /// The authentication mode to use
        #[clap(arg_enum)]
        auth_mode: AuthMode,
        /// Show the secret on standard output instead of the device. NOT RECOMMENDED!
        #[clap(long)]
        stdout: bool,
    },

    /// Show the version information of this Coldcard
    Version,

    /// Show the master fingerprint for this wallet
    Xfp,

    /// Show the xpub (default: master)
    Xpub {
        /// The optional derivation path
        path: Option<String>,

        #[clap(arg_enum)]
        /// The extended key version to optionally convert to.
        version: Option<XpubVersion>,

        /// Include the fingerprint. The output will be two lines.
        #[clap(long)]
        xfp: bool,
    },
}

#[derive(clap::ArgEnum, Clone)]
enum AddressFormat {
    Legacy,
    Wrapped,
    Segwit,
}

impl From<AddressFormat> for protocol::AddressFormat {
    fn from(value: AddressFormat) -> Self {
        match value {
            AddressFormat::Legacy => protocol::AddressFormat::P2PKH,
            AddressFormat::Wrapped => protocol::AddressFormat::P2WPKH_P2SH,
            AddressFormat::Segwit => protocol::AddressFormat::P2WPKH,
        }
    }
}

#[derive(clap::ArgEnum, Clone)]
#[allow(clippy::upper_case_acronyms)]
enum AuthMode {
    TOTP,
    HOTP,
    HMAC,
}

#[derive(clap::ArgEnum, Clone)]
enum SignMode {
    /// Visualize only, no signing
    Visualize,
    /// Visualize with signature
    VisualizeSigned,
    /// Finalize the transaction
    Finalize,
}

impl From<AuthMode> for protocol::AuthMode {
    fn from(mode: AuthMode) -> Self {
        match mode {
            AuthMode::TOTP => protocol::AuthMode::TOTP,
            AuthMode::HOTP => protocol::AuthMode::HOTP,
            AuthMode::HMAC => protocol::AuthMode::HMAC,
        }
    }
}

impl From<&SignMode> for coldcard::SignMode {
    fn from(mode: &SignMode) -> Self {
        match mode {
            SignMode::Visualize => coldcard::SignMode::Visualize,
            SignMode::VisualizeSigned => coldcard::SignMode::VisualizeSigned,
            SignMode::Finalize => coldcard::SignMode::Finalize,
        }
    }
}

#[derive(Clone, clap::ArgEnum)]
enum XpubVersion {
    Xpub,
    Ypub,
    Zpub,
    Tpub,
    Upub,
    Vpub,
}

impl From<XpubVersion> for xpub_version::Version {
    fn from(value: XpubVersion) -> Self {
        match value {
            XpubVersion::Xpub => Self::Xpub,
            XpubVersion::Ypub => Self::Ypub,
            XpubVersion::Zpub => Self::Zpub,
            XpubVersion::Tpub => Self::Tpub,
            XpubVersion::Upub => Self::Upub,
            XpubVersion::Vpub => Self::Vpub,
        }
    }
}

fn main() -> Result<(), Error> {
    env_logger::init();

    let cli = Cli::parse();

    handle(cli)
}

fn handle(cli: Cli) -> Result<(), Error> {
    let mut api = coldcard::Api::new()?;
    let serials = api.detect()?;

    // Commands we can handle without a Coldcard connection.
    match cli.command {
        Command::List => {
            for cc in serials {
                println!("{}", cc.as_ref());
            }

            return Ok(());
        }

        #[cfg(target_os = "linux")]
        Command::InstallUdevRules => {
            const UDEV_FILE: &str = "/etc/udev/rules.d/51-coinkite.rules";

            if std::path::Path::new(UDEV_FILE).exists() {
                eprintln!("udev rules already installed");
            } else {
                match std::fs::File::create(UDEV_FILE) {
                    Ok(mut file) => {
                        file.write_all(include_bytes!("../51-coinkite.rules"))?;
                        eprintln!("udev rules installed");
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                        eprintln!("Permission denied. Try with sudo?");
                    }
                    Err(err) => eprintln!("error: {}", err),
                }
            }

            return Ok(());
        }

        _ => {}
    }

    let sn = match cli.serial {
        Some(sn) => serials.into_iter().find(|dev_sn| sn == dev_sn.as_ref()),
        None => serials.into_iter().next(),
    }
    .ok_or(Error::NoColdcardDetected)?;

    let (mut cc, xpub_info) = api.open(
        sn,
        Some(Options {
            resync_on_open: true,
            ..Default::default()
        }),
    )?;

    // check for MITM if requested
    let expected_xpub = cli.xpub;
    match (
        expected_xpub.as_deref(),
        xpub_info.as_ref().map(|x| &x.xpub),
    ) {
        (Some(expected), Some(actual)) => {
            if expected != actual {
                eprintln!("The expected xpub does not match the one on the device");
                return Err(Error::MitmInProgress);
            } else {
                let mitm = cc.check_mitm(expected)?;
                if mitm {
                    eprintln!("WARNING - POSSIBLE MITM IN PROGRESS");
                    return Err(Error::MitmInProgress);
                }
            }
        }
        (Some(_), None) => {
            eprintln!("An xpub was passed but there is no secret on the device yet; MITM check not possible");
        }
        _ => {}
    }

    match cli.command {
        Command::Address { path, format } => {
            let path = protocol::DerivationPath::new(&path)?;
            let address = cc.address(path, format.into())?;
            println!("{}", address);
        }

        Command::AuthToken { username, token } => {
            let totp_time = (now() / 30) as u32;
            let username = protocol::Username::new(username)?;
            let token = match token {
                Some(token) => parse_6_digit_token(&token),
                None => parse_6_digit_token(
                    &rpassword::prompt_password("Enter a 6-digit code:\n").unwrap(),
                ),
            }?;

            cc.user_auth(username, token, totp_time)?;
            eprintln!("OK");
        }

        Command::Backup { path } => {
            cc.start_backup()?;
            print_waiting();

            let Backup { data, sha256 } = loop {
                sleep();
                let backup = cc.get_backup()?;
                match backup {
                    Some(backup) => break backup,
                    None => continue,
                }
            };

            let mut file = File::create(&path)?;
            file.write_all(&data)?;

            eprintln!(
                "Saved the backup to {};\nchecksum: {}",
                path.to_str().unwrap_or("Path error"),
                hex::encode(sha256)
            );
        }

        Command::Bag => {
            let bag = cc.bag_number()?;
            println!("{}", bag);
        }

        Command::Chain => {
            let blockchain = cc.blockchain()?;
            println!("{}", blockchain);
        }

        Command::DeleteUser { username } => {
            let username = protocol::Username::new(username)?;
            cc.delete_username(username)?;
            eprintln!("OK - deleted if it was there");
        }

        Command::Hsm => {
            let policy = cc.hsm_policy()?;
            println!("{}", policy);
        }

        Command::HsmStart { path: Some(path) } => {
            let mut file = File::open(path)?;
            let mut policy = vec![];
            file.read_to_end(&mut policy)?;

            cc.hsm_start(Some(&policy))?;
            eprintln!("OK");
        }

        Command::HsmStart { path: None } => {
            cc.hsm_start(None)?;
            eprintln!("OK");
        }

        #[cfg(target_os = "linux")]
        Command::InstallUdevRules => unreachable!("handled earlier"),

        Command::List => unreachable!("handled earlier if no command"),

        Command::LocalConf { psbt, next_code } => {
            let data = load_psbt(&psbt)?;
            let psbt_checksum = util::sha256(&data);

            let next_code = match next_code {
                Some(next_code) => next_code,
                None => {
                    let policy = cc.hsm_policy()?;
                    let policy = json::parse(&policy).unwrap();
                    policy["next_local_code"].as_str().unwrap().to_owned()
                }
            };

            let code = calc_local_pincode(&psbt_checksum, &next_code)?;
            println!("{}", code);
        }

        Command::Locker { utf8 } => {
            let data = cc.locker()?;
            let encoded = if utf8 {
                String::from_utf8(data).expect("The locker contents are not valid UTF-8")
            } else {
                hex::encode(&data)
            };
            println!("{}", encoded);
        }

        Command::Logout => {
            cc.logout()?;
            eprintln!("OK");
        }

        Command::Message {
            message,
            path,
            address_format,
            armor,
        } => {
            let raw_msg = protocol::Message::new(&message)?;
            let path = path
                .as_ref()
                .map(|p| protocol::DerivationPath::new(p))
                .transpose()?;

            print_waiting();
            cc.sign_message(raw_msg, path, address_format.into())?;

            let (signature, address) = loop {
                sleep();
                let signature = cc.get_signed_message()?;
                match signature {
                    Some(SignedMessage { signature, address }) => break (signature, address),
                    None => continue,
                }
            };

            let encoded_sig = b64_encode(&signature);
            if armor {
                let armor = format!(
                    "\
                -----BEGIN BITCOIN SIGNED MESSAGE-----\n\
                {message}\n\
                -----BEGIN SIGNATURE-----\n\
                {address}\n\
                {encoded_sig}\n\
                -----END BITCOIN SIGNED MESSAGE-----"
                );
                println!("{}", armor);
            } else {
                println!("{}", encoded_sig);
            }
        }

        Command::Passphrase { stdin } => {
            let pass = if stdin {
                let mut pass = String::new();
                std::io::stdin().read_line(&mut pass)?;
                pass.trim().to_owned()
            } else {
                println!("Enter the passphrase (input will not be shown):");
                rpassword::read_password()?
            };

            print_waiting();
            let passphrase = protocol::Passphrase::new(pass)?;
            cc.set_passphrase(passphrase)?;

            let xpub = loop {
                sleep();
                let xpub = cc.get_passphrase_done()?;
                match xpub {
                    Some(xpub) => break xpub,
                    None => continue,
                }
            };

            eprintln!("The new xpub is:");
            println!("{}", xpub);
        }

        Command::Pubkey { path } => {
            let path = protocol::DerivationPath::new(&path)?;
            let xpub = cc.xpub(Some(path))?;
            let pk = util::decode_xpub(&xpub).expect("Unable to decode xpub; Coldcard error");
            let encoded = hex::encode(pk.to_sec1_bytes());
            println!("{encoded}");
        }

        Command::Reboot => {
            cc.reboot()?;
            eprintln!("Rebooting...");
        }

        Command::Sign {
            psbt_in,
            psbt_out,
            mode,
            base64,
        } => {
            let psbt = load_psbt(&psbt_in)?;
            let sign_mode = (&mode).into();

            cc.sign_psbt(&psbt, sign_mode)?;

            let tx = loop {
                sleep();
                let tx = cc.get_signed_tx()?;
                match tx {
                    Some(tx) => break tx,
                    None => continue,
                }
            };

            let tx_string = match mode {
                SignMode::Visualize => String::from_utf8(tx).unwrap(),
                SignMode::VisualizeSigned => String::from_utf8(tx).unwrap(),
                SignMode::Finalize if base64 => b64_encode(&tx),
                SignMode::Finalize => hex::encode(&tx),
            };

            if let Some(psbt_out) = psbt_out {
                let mut out = File::create(psbt_out)?;
                out.write_all(tx_string.as_bytes())?;
            } else {
                println!("{}", tx_string);
            }
        }

        Command::Test => {
            eprintln!("Testing the connection...");
            cc.test()?;
            eprintln!("OK")
        }

        Command::Upgrade { path: Some(path) } => {
            let firmware = firmware::Firmware::load_dfu(&path)?;
            ProgressBar::new(1, 2, "📁 Read    ").finish();
            complete_upgrade(cc, firmware, 2)?;
        }

        Command::Upgrade { path: None } => {
            eprintln!(
                "Searching {} for available firmwares...",
                console::Style::new()
                    .underlined()
                    .bold()
                    .apply_to(fw_upgrade::DOWNLOADS)
            );

            let releases = match fw_upgrade::Release::find() {
                Ok(releases) => releases,
                Err(_) => {
                    eprintln!("Cannot fetch available releases.");
                    return Ok(());
                }
            };

            let cc_info = cc.version()?;

            let our_fw = cc_info
                .lines()
                .nth(1)
                .and_then(|v| v.parse::<semver::Version>().ok());
            let our_model = cc_info.lines().nth(4);

            let bold = console::Style::new().bold();

            let mode = prompt(
                "Auto determine the best firmware or select manually?",
                &["auto", "manual"],
            );

            eprintln!(
                "Our model and firmware: {} - {}",
                bold.apply_to(our_model.unwrap_or("unknown")),
                bold.apply_to(
                    our_fw
                        .as_ref()
                        .map(|v| format!("v{}", v))
                        .unwrap_or("unknown".to_owned())
                )
            );

            let release = if mode == "auto" {
                match fw_upgrade::best_match(&releases, our_model) {
                    Some(release) => {
                        eprintln!(
                            "Best firmware match: {} ({}) ",
                            bold.apply_to(format!("v{}", release.version)),
                            release.name
                        );

                        if Some(&release.version) <= our_fw.as_ref() {
                            eprintln!("The device already has the latest firmware.");
                            return Ok(());
                        }

                        release
                    }
                    None => {
                        warn(
                        "Cannot determine a good firmware match for your device. Proceed manually."
                    );
                        return Ok(());
                    }
                }
            } else {
                eprintln!();
                for (i, r) in releases.iter().enumerate() {
                    eprintln!(
                        "({i})\t{}\t{}",
                        r.name,
                        r.is_edge.then_some("(* experimental)").unwrap_or_default()
                    );
                }

                eprintln!();
                warn("Ensure that the chosen firmware is appropriate for your device.");
                eprint!(
                    "Enter a number next to the wanted firmware (0-{}): ",
                    releases.len() - 1
                );

                let mut choice = String::new();
                std::io::stdin().read_line(&mut choice).unwrap();

                match choice.trim().parse::<usize>() {
                    Ok(i) if i < releases.len() => {
                        let r = &releases[i];
                        eprintln!("Selected firmware: {} ({}) ", r.version, r.name);
                        r
                    }
                    _ => {
                        eprintln!("ERROR: Invalid choice.");
                        return Ok(());
                    }
                }
            };

            if release.is_edge {
                warn("The selected release is \"edge\" (experimental).");
            }

            let choice = prompt("Proceed?", &["Yes", "no"]);
            if choice != "Yes" {
                eprintln!("Aborted");
                return Ok(());
            }

            let pb = ProgressBar::new(1, 2, "⬇️  Download");

            let fw_bytes = release
                .download(|downloaded, total| {
                    pb.update(downloaded as u64, total as u64);
                })
                .unwrap();

            pb.finish();

            let pb = ProgressBar::new(2, 3, "🔒 Verify  ");

            match release.verify(&fw_bytes) {
                Ok(_) => pb.finish(),
                Err(err) => {
                    pb.finish_with_err(err);
                    return Ok(());
                }
            }

            let firmware = firmware::Firmware::parse_dfu(&mut std::io::Cursor::new(fw_bytes))?;

            complete_upgrade(cc, firmware, 3)?;
        }

        Command::User {
            username,
            auth_mode,
            stdout,
        } => {
            let validated_username = protocol::Username::new(&username)?;
            let auth_mode: protocol::AuthMode = auth_mode.into();

            let secret = cc.create_username(validated_username, auth_mode, !stdout)?;

            if let Some(secret) = secret {
                let serial = cc.serial_number();
                let mode = match auth_mode {
                    protocol::AuthMode::TOTP => "totp",
                    protocol::AuthMode::HOTP => "hotp",
                    protocol::AuthMode::HMAC => "hmac",
                };
                match auth_mode {
                    protocol::AuthMode::HMAC => println!("{}", secret),
                    _ => println!(
                        "otpauth://{mode}/{username}?secret={secret}&issuer=Coldcard%20{serial}"
                    ),
                }
            } else {
                eprintln!("OK - the secret is shown on the device");
            }
        }

        Command::Version => {
            let version = cc.version()?;
            println!("{}", version);
        }

        Command::Xfp => {
            if let Some(XpubInfo { fingerprint, .. }) = xpub_info {
                let hex = hex::encode_upper(fingerprint);
                println!("{}", hex);
            }
        }

        Command::Xpub { path, version, xfp } => {
            let path = path
                .map(|p| protocol::DerivationPath::new(&p))
                .transpose()?;
            let mut xpub = cc.xpub(path)?;

            if xfp {
                let pk = util::decode_xpub(&xpub).expect("Unable to decode xpub; Coldcard error");
                let xfp = util::xfp(&pk);
                let hex = hex::encode_upper(xfp);
                println!("{}", hex);
            }

            if let Some(version) = version {
                xpub = xpub_version::convert_bytes(&xpub, version.into())?;
            }
            println!("{}", xpub);
        }
    }

    Ok(())
}

fn now() -> u64 {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    let now = SystemTime::now();
    let now = now.duration_since(UNIX_EPOCH).expect("Time error");
    now.as_secs()
}

fn calc_local_pincode(psbt_checksum: &[u8; 32], next_code: &str) -> Result<String, Error> {
    let key = b64_decode(next_code).map_err(|_| Error::InvalidBase64)?;
    let digest = hmac_sha256::HMAC::mac(psbt_checksum, key);
    let last = digest[28..32].try_into().expect("cannot fail");
    let num = (u32::from_be_bytes(last) & 0x7FFFFFFF) % 1000000;
    Ok(format!("{:#06}", num))
}

fn sleep() {
    std::thread::sleep(std::time::Duration::from_millis(250));
}

fn parse_6_digit_token(s: &str) -> Result<protocol::AuthToken, Error> {
    if s.len() == 6 && s.chars().all(|c| c.is_ascii_digit()) {
        Ok(protocol::AuthToken::new(s)?)
    } else {
        Err(Error::NotAuthToken)
    }
}

fn load_psbt(path: &PathBuf) -> Result<Vec<u8>, Error> {
    let mut file = File::open(path)?;
    let mut header = vec![0_u8; 10];
    file.read_exact(&mut header)?;
    file.seek(SeekFrom::Start(0))?;
    let mut data = vec![];
    file.read_to_end(&mut data)?;

    fn trimmed(d: &mut Vec<u8>) {
        // the danger here is the user will paste into something like Vim
        // which will append a newline (invalid in both b64 or hex)
        while let Some(c) = d.last() {
            if c == &b'\n' || c == &b'\r' {
                d.pop();
            } else {
                break;
            }
        }
    }

    if &header[..10] == b"70736274ff" || &header[..10] == b"70736274FF" {
        trimmed(&mut data);
        hex::decode(&data).map_err(|_| Error::InvalidPSBT)
    } else if &header[..6] == b"cHNidP" {
        trimmed(&mut data);
        b64_decode(&data).map_err(|_| Error::InvalidPSBT)
    } else if &header[..5] == b"psbt\xff" {
        Ok(data)
    } else {
        Err(Error::InvalidPSBT)
    }
}

fn complete_upgrade(
    mut cc: coldcard::Coldcard,
    firmware: firmware::Firmware,
    step: u16,
) -> Result<(), Error> {
    let pb = ProgressBar::new(step, step, "💾 Flash   ");
    let size = firmware.bytes().len();

    cc.upgrade(firmware, |uploaded, _| {
        pb.update(uploaded as u64, size as u64);
    })?;

    pb.finish();

    eprintln!("Proceed on the Coldcard to complete the process.");
    cc.reboot()?;

    Ok(())
}

fn print_waiting() {
    eprintln!("Waiting for OK on the Coldcard...");
}

fn warn(text: &str) {
    let prefix = console::Style::new().color256(202).bold();
    eprintln!("{} {}", prefix.apply_to("WARNING:"), text);
}

#[derive(Debug)]
enum Error {
    Coldcard(coldcard::Error),
    Derivation(derivation_path::Error),
    Encode(protocol::EncodeError),
    Firmware(firmware::Error),
    UnexpectedResponse(protocol::Response),
    MitmInProgress,
    Io(std::io::Error),
    InvalidBase64,
    NotAuthToken,
    InvalidPSBT,
    NoColdcardDetected,
    VersionConvert(xpub_version::Error),
}

impl From<coldcard::Error> for Error {
    fn from(error: coldcard::Error) -> Self {
        Self::Coldcard(error)
    }
}

impl From<derivation_path::Error> for Error {
    fn from(error: derivation_path::Error) -> Self {
        Self::Derivation(error)
    }
}

impl From<firmware::Error> for Error {
    fn from(error: firmware::Error) -> Self {
        Self::Firmware(error)
    }
}

impl From<Response> for Error {
    fn from(response: Response) -> Self {
        Self::UnexpectedResponse(response)
    }
}

impl From<protocol::EncodeError> for Error {
    fn from(error: protocol::EncodeError) -> Self {
        Self::Encode(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<xpub_version::Error> for Error {
    fn from(error: xpub_version::Error) -> Self {
        Self::VersionConvert(error)
    }
}

fn prompt<'a>(text: &'static str, choices: &'a [&str]) -> &'a str {
    let bold = console::Style::new().bold();

    let formatted = choices
        .iter()
        .map(|c| {
            let (first, rest) = c.split_at(1);
            format!("[{}]{}", bold.apply_to(first), rest)
        })
        .collect::<Vec<_>>()
        .join("/");

    let mut input = String::new();
    loop {
        eprint!("{text} {formatted} ");
        input.clear();
        std::io::stdin().read_line(&mut input).unwrap();
        let choice = input.trim().chars().next();
        if let Some(i) = choices.iter().position(|c| c.chars().next() == choice) {
            return choices[i];
        }
    }
}

struct ProgressBar {
    pb: indicatif::ProgressBar,
}

impl ProgressBar {
    pub fn new(step: u16, steps: u16, action: &'static str) -> Self {
        const PROG_TEMPLATE: &str =
                "{prefix:.bold}: {spinner:.green} [{bar:40.green}] [{percent}%] ({bytes}/{total_bytes})";

        Self {
            pb: indicatif::ProgressBar::new(100)
                .with_style(indicatif::ProgressStyle::with_template(PROG_TEMPLATE).unwrap())
                .with_finish(indicatif::ProgressFinish::Abandon)
                .with_prefix(format!("[{step}/{steps}] {action}")),
        }
    }

    fn update(&self, pos: u64, length: u64) {
        self.pb.update(|s| {
            s.set_pos(pos);
            s.set_len(length);
        });
    }

    pub fn finish(self) {
        const FIN_TEMPLATE: &str = "{prefix:.bold}: Complete ✅";

        self.pb
            .set_style(indicatif::ProgressStyle::with_template(FIN_TEMPLATE).unwrap());
        self.pb.tick();
    }

    pub fn finish_with_err(self, err: &str) {
        let err = format!("{{prefix:.bold}}: {} ❌", err);

        self.pb
            .set_style(indicatif::ProgressStyle::with_template(&err).unwrap());
        self.pb.tick();
    }
}

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(data: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(data)
}
