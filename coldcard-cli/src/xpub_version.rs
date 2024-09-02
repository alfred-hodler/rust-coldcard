use base58::FromBase58;
use base58::ToBase58;
use coldcard::util::sha256;

/// Some of the possible extended key version bytes.
#[derive(Debug, Clone, Copy)]
pub enum Version {
    Xpub,
    Ypub,
    Zpub,
    Tpub,
    Upub,
    Vpub,
}

impl Version {
    /// Returns the version bytes for a particular exended key version.
    fn bytes(&self) -> [u8; 4] {
        match self {
            Version::Xpub => XPUB,
            Version::Ypub => YPUB,
            Version::Zpub => ZPUB,
            Version::Tpub => TPUB,
            Version::Upub => UPUB,
            Version::Vpub => VPUB,
        }
    }
}

const XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
const YPUB: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
const ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
const TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
const UPUB: [u8; 4] = [0x04, 0x4A, 0x52, 0x62];
const VPUB: [u8; 4] = [0x04, 0x5F, 0x1C, 0xF6];

/// Converts an extended key to a different version.
pub fn convert_bytes(s: &str, to: Version) -> Result<String, Error> {
    let mut decoded = s.from_base58().map_err(|_| Error::InvalidBase58)?;
    if decoded.len() != 82 {
        return Err(Error::InvalidLength);
    }

    decoded[0..4].copy_from_slice(&to.bytes());
    let checksum = sha256(&sha256(&decoded[0..78]));
    decoded[78..82].copy_from_slice(&checksum[0..4]);
    Ok(decoded.to_base58())
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    InvalidBase58,
    InvalidLength,
}

#[cfg(test)]
mod test {
    use crate::xpub_version::Version;

    use super::convert_bytes;

    #[test]
    fn version_conversion() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

        let zpub = convert_bytes(xpub, Version::Zpub).unwrap();
        assert_eq!(zpub, "zpub6jftahH18ngZxUuv6oSniLNrBCSSE1B4EEU59bwTCEt8x6aS6b2mdfLxbS4QS53g85SWWP6wexqeer516433gYpZQoJie2tcMYdJ1SYYYAL");

        let ypub = convert_bytes(xpub, Version::Ypub).unwrap();
        assert_eq!(ypub, "ypub6QqdH2c5z7967BioGSfAWFHM1EHzHPBZK7wrND3ZpEWFtzmCqvsD1bgpaE6pSAPkiSKhkuWPCJV6mZTSNMd2tK8xYTcJ48585pZecmSUzWp");

        let tpub = convert_bytes(xpub, Version::Tpub).unwrap();
        assert_eq!(tpub, "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp");

        let vpub = convert_bytes(xpub, Version::Vpub).unwrap();
        assert_eq!(vpub, "vpub5SLqN2bLY4WeZJ9SmNJHsyzqVKreTXD4ZnPC22MugDNcjhKX5xNX9QiQWcE4SSRzVWyHWUihpKRT7hckDGNzVc69wSX2JPcfGeNiT5c2XZy");

        let orig_xpub = convert_bytes(&zpub, Version::Xpub).unwrap();
        assert_eq!(xpub, orig_xpub);
    }
}
