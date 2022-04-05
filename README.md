# Coldcard Interface Library

`rust-coldcard` is a library for interfacing with the [Coldcard](https://coldcard.com/) hardware wallet. It includes an optional CLI executable.

## Usage

```rust
use coldcard;
use coldcard::protocol;

// detect all connected Coldcards
let serials = coldcard::detect()?;

// open a particular one
let mut coldcard = serials[0].open()?;

// set a passphrase
coldcard.set_passphrase(protocol::Passphrase::new("secret")?)?;

// after the user confirms
let xpub = coldcard.get_passphrase_done()?;

if let Some(xpub) = xpub {
    println!("The new XPUB is: {}", xpub);
}

// secure logout
coldcard.logout()?;
```

## CLI

To build the CLI executable, use:

```bash
$ cargo build --features cli --release
```

The CLI can also be installed with `cargo` using the `install` command.

To explore the capabilities of the CLI, use:

```bash
$ coldcard --help

coldcard 0.1.0
Coldcard Interface Library in Rust

USAGE:
    coldcard [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -h, --help               Print help information
        --serial <SERIAL>    The Coldcard serial number to operate on (default: first one found)
    -V, --version            Print version information
        --xpub <XPUB>        Perform a MITM check against an xpub

SUBCOMMANDS:
    address        Show the address for a derivation path
    auth-token     Authenticate a specific user using a 6-digit token (for HSM)
    backup         Initiate the backup process and create an encrypted 7z file
    bag            Show the bag number the Coldcard arrived in
    chain          Show the configured blockchain
    delete-user    Delete a specific HSM user
    help           Print this message or the help of the given subcommand(s)
    hsm            Show the current HSM policy
    hsm-start      Starts the HSM mode (with a specific policy)
    list           List the serial numbers of connected Coldcards
    local-conf     Generate a 6-digit code for PSBT signing in HSM mode
    locker         Get the hex contents of the storage locker (HSM mode only)
    logout         Securely log out of the Coldcard
    message        Sign a text message with a specific derivation path
    passphrase     Set a BIP39 passphrase
    pubkey         Show the pubkey for a derivation path
    reboot         Reboot the Coldcard
    sign           Sign a spending PSBT transaction
    test           Test USB connection
    upgrade        Upgrade the firmware
    user           Create a new HSM user. The secret is generated on the device
    version        Show the version information of this Coldcard
    xfp            Show the master fingerprint for this wallet
    xpub           Show the xpub (default: master)
```


## Contributing

Contributions are welcome. Before making large changes, please open an issue first.

## Disclaimer

This is not an official project and comes with no warranty whatsoever.