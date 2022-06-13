use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use coldcard::Coldcard;

use serde::{Deserialize, Serialize};

use crate::Command;
use crate::Error;
use crate::{Cli, SignMode};

#[derive(Serialize, Deserialize)]
pub(crate) struct RemoteRequest {
    password: String,
    command: RemoteCommand,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum RemoteCommand {
    Logout,
    SignPsbt { mode: SignMode, psbt: Vec<u8> },
}

#[derive(Serialize, Deserialize)]
pub enum RemoteResponse {
    Ok,
    Psbt(Vec<u8>),
    BadAuth,
    Refused,
    ServerError,
}

/// Handles a CLI command meant for a remote service.
pub(crate) fn handle(cli: Cli) -> Result<(), Error> {
    if !is_remote(&cli.command) {
        return Err(RemoteError::NotRemoteCommand.into());
    }

    let target = cli.hidden_service.unwrap();
    let proxy = format!("localhost:{}", cli.socks_port);
    let mut stream = socks::Socks5Stream::connect(&proxy, target.as_str())
        .map_err(|_| RemoteError::TorConnectionProblem)?;

    fn send_receive<T>(stream: &mut T, request: RemoteRequest) -> Result<RemoteResponse, Error>
    where
        T: Read + Write,
    {
        let data = bincode::serialize(&request)?;
        stream.write_all(&(data.len() as u32).to_le_bytes())?;
        stream.write_all(&data)?;

        let mut response_len = [0_u8; 4];
        stream.read_exact(&mut response_len)?;
        let response_len = u32::from_le_bytes(response_len) as usize;

        let mut response = vec![0_u8; response_len];
        stream.read_exact(&mut response)?;

        let response: RemoteResponse = bincode::deserialize(&response)?;

        match response {
            RemoteResponse::BadAuth => Err(RemoteError::BadAuth.into()),
            RemoteResponse::Refused => Err(RemoteError::Refused.into()),
            response => Ok(response),
        }
    }

    let password = rpassword::prompt_password("Enter the password for the remote service: ")?;

    match cli.command {
        Command::Logout => {
            let response = send_receive(
                &mut stream,
                RemoteRequest {
                    password,
                    command: RemoteCommand::Logout,
                },
            )?;

            match response {
                RemoteResponse::Ok => {
                    eprintln!("OK");
                    return Ok(());
                }
                _ => panic!("wrong response"),
            }
        }

        Command::Sign {
            psbt_in,
            mode,
            base64,
            psbt_out,
        } => {
            let psbt = crate::load_psbt(&psbt_in)?;

            let response = send_receive(
                &mut stream,
                RemoteRequest {
                    password,
                    command: RemoteCommand::SignPsbt {
                        mode: mode.clone(),
                        psbt,
                    },
                },
            )?;

            let tx = match response {
                RemoteResponse::Psbt(tx) => tx,
                _ => panic!("wrong response"),
            };

            let tx_string = match mode {
                SignMode::Visualize => String::from_utf8(tx).unwrap(),
                SignMode::VisualizeSigned => String::from_utf8(tx).unwrap(),
                SignMode::Finalize if base64 => base64::encode(&tx),
                SignMode::Finalize => hex::encode(&tx),
            };

            if let Some(psbt_out) = psbt_out {
                let mut out = File::create(&psbt_out)?;
                out.write_all(tx_string.as_bytes())?;
            } else {
                println!("{}", tx_string);
            }
        }

        _ => return Err(RemoteError::NotRemoteCommand.into()),
    };

    Ok(())
}

/// Handles remote requests (server mode).
pub(crate) fn listen(mut cc: Coldcard, password: &str) -> Result<(), Error> {
    use libtor::{HiddenServiceVersion, Tor, TorAddress, TorFlag};

    let tor_port = 8000;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let internal_port = listener.local_addr()?.port();

    let mut tor_dir = dirs::data_local_dir().expect("No data dir");
    tor_dir.push("cc-tor");

    let mut hs_dir = tor_dir.clone();
    hs_dir.push("hs");

    Tor::new()
        .flag(TorFlag::DataDirectory(tor_dir.to_str().unwrap().to_owned()))
        .flag(TorFlag::HiddenServiceDir(
            hs_dir.to_str().unwrap().to_owned(),
        ))
        .flag(TorFlag::HiddenServiceVersion(HiddenServiceVersion::V3))
        .flag(TorFlag::HiddenServicePort(
            TorAddress::Port(tor_port),
            Some(TorAddress::Port(internal_port)).into(),
        ))
        .start_background();

    hs_dir.push("hostname");
    // wait for the keys to be generated if first time
    let hostname = loop {
        let hostname = std::fs::read(&hs_dir);
        if let Ok(hostname) = hostname {
            let hostname = String::from_utf8(hostname).expect("hostname not utf-8");
            break hostname;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    };

    println!(
        "------------------------------------------------------------------------------------"
    );
    println!("| Serving at {}:{}   |", hostname.trim(), tor_port);
    println!(
        "------------------------------------------------------------------------------------"
    );

    fn handle(mut stream: TcpStream, cc: &mut Coldcard, password: &str) -> Result<bool, Error> {
        let mut content_len = [0_u8; 4];

        stream.read_exact(&mut content_len)?;
        let content_len = u32::from_le_bytes(content_len) as usize;

        let mut content = vec![0; content_len as usize];
        stream.read_exact(&mut content)?;

        let request: RemoteRequest = bincode::deserialize(&content)?;

        if request.password != password {
            let response_bytes = bincode::serialize(&RemoteResponse::BadAuth)?;
            stream.write_all(&(response_bytes.len() as u32).to_le_bytes())?;
            stream.write_all(&response_bytes)?;
            eprintln!("bad auth with pwd: {}", request.password);
            return Ok(false);
        }

        let (logout, response) = match request.command {
            RemoteCommand::Logout => (true, RemoteResponse::Ok),

            RemoteCommand::SignPsbt { mode, psbt } => {
                cc.sign_psbt(&psbt, (&mode).into())?;

                loop {
                    crate::sleep();
                    let tx = cc.get_signed_tx();
                    match tx {
                        Ok(Some(tx)) => break (false, RemoteResponse::Psbt(tx)),
                        Ok(None) => continue,
                        Err(coldcard::Error::UnexpectedResponse(_)) => {
                            break (false, RemoteResponse::Refused)
                        }
                        Err(_) => break (false, RemoteResponse::ServerError),
                    }
                }
            }
        };

        let response_bytes = bincode::serialize(&response)?;

        stream.write_all(&(response_bytes.len() as u32).to_le_bytes())?;
        stream.write_all(&response_bytes)?;

        Ok(logout)
    }

    loop {
        let (stream, _) = listener.accept()?;
        let result = handle(stream, &mut cc, password);

        match result {
            Ok(true) => {
                cc.logout()?;
                return Ok(());
            }
            Ok(false) => {}
            Err(error) => eprintln!("{:?}", error),
        }

        // throttle incoming requests to prevent grinding attacks
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn is_remote(command: &Command) -> bool {
    match command {
        Command::Logout => true,
        Command::Sign { .. } => true,
        _ => false,
    }
}

#[derive(Debug)]
pub enum RemoteError {
    NotRemoteCommand,
    BadAuth,
    Bincode(bincode::Error),
    Refused,
    TorConnectionProblem,
}

impl From<bincode::Error> for Error {
    fn from(error: bincode::Error) -> Self {
        Error::Remote(RemoteError::Bincode(error))
    }
}
