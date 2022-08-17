# Coldcard Interface Library

`coldcard` is a library for interfacing with the [Coldcard](https://coldcard.com/) hardware wallet.

## Usage

```rust
use coldcard::protocol;

// detect all connected Coldcards
let serials = coldcard::detect()?;

// open a particular one
let (mut coldcard, master_xpub) = serials[0].open(None)?;

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

This project also offers a CLI tool. See the project's own crate for more information.

Install it with:

```bash
$ cargo install coldcard-cli
```

## Contributing

Contributions are welcome. Before making large changes, please open an issue first.

## Disclaimer

This is not an official project and comes with no warranty whatsoever.