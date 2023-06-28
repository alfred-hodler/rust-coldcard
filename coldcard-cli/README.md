# Coldcard CLI

`coldcard-cli` is a CLI tool for interfacing with the [Coldcard](https://coldcard.com/) hardware wallet.


Install it with:

```bash
$ cargo install coldcard-cli
```

Usage:
```bash
$ coldcard --help

coldcard-cli 0.7.0
Coldcard Wallet CLI Tool

USAGE:
    coldcard [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

        --serial <SERIAL>
            The Coldcard serial number to operate on (default: first one found)

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
    sign           Sign a spending PSBT transaction
    test           Test USB connection
    upgrade        Upgrade the firmware
    user           Create a new HSM user. The secret is generated on the device
    version        Show the version information of this Coldcard
    xfp            Show the master fingerprint for this wallet
    xpub           Show the xpub (default: master)
```

## Linux Specific Instructions

In order to be able to detect a Coldcard device on a Linux system, [51-coinkite.rules](../51-coinkite.rules) must be placed in `/etc/udev/rules.d/`.

Two mutually exclusive HID backends are supported and can be turned on using the following features:

* `coldcard/linux-static-hidraw` (default)
* `coldcard/linux-static-libusb` (potential issues with [unclear error messages](https://github.com/libusb/hidapi/blob/f2e2b5b4d4caa9942ad2cd594da00956b51f0ca6/libusb/hid.c#L1637))

## Logging

To see log output, run the program with the `RUST_LOG=$level` environment variable. This uses the `env_logger` crate.

## Library

This project also offers a library for Rust integration. See the `coldcard` crate for more information.

## Contributing

Contributions are welcome. Before making large changes, please open an issue first.

## Disclaimer

This is not an official project and comes with no warranty whatsoever.
