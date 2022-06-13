# Coldcard CLI

`coldcard-cli` is a CLI tool for interfacing with the [Coldcard](https://coldcard.com/) hardware wallet.


Install it with:

```bash
$ cargo install coldcard-cli
```

Usage:
```bash
$ coldcard --help

coldcard-cli 0.3.0
Coldcard Wallet CLI Tool

USAGE:
    coldcard [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

        --hidden-service <HIDDEN_SERVICE>
            The .onion address representing a remote Coldcard to connect to

        --serial <SERIAL>
            The Coldcard serial number to operate on (default: first one found)

        --socks-port <SOCKS_PORT>
            The socks5 port of the local Tor proxy when executing a remote command [default: 9150]

    -V, --version
            Print version information

        --xpub <XPUB>
            Perform a MITM check against an xpub

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
    server         Bind the Coldcard to a V3 Tor Hidden Service for remote interaction
    sign           Sign a spending PSBT transaction
    test           Test USB connection
    upgrade        Upgrade the firmware
    user           Create a new HSM user. The secret is generated on the device
    version        Show the version information of this Coldcard
    xfp            Show the master fingerprint for this wallet
    xpub           Show the xpub (default: master)
```

## Remote mode

It is possible to start the CLI in the server mode, binding it to a locally connected Coldcard. This
creates a V3 Tor hidden service and exposes it on port 8000. It then becomes possible to issue a
limited subset of CLI commands to this service through Tor.

The server would execute:

```bash
$ coldcard server password123
Serving at ccbr3lbye4rrtynoih4mhbligh6ays3s2w6ns7pzp7ouvj7kg5viizad.onion:8000
```

The client might then initiate remote PSBT signing:

```bash
$ coldcard --hidden-service ccbr3lbye4rrtynoih4mhbligh6ays3s2w6ns7pzp7ouvj7kg5viizad.onion:8000 sign ~/testnet-182b6376.psbt finalize
```

## Library

This project also offers a library for Rust integration. See the `coldcard` crate for more information.

## Contributing

Contributions are welcome. Before making large changes, please open an issue first.

## Disclaimer

This is not an official project and comes with no warranty whatsoever.
