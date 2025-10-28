//! Miscellaneous utility functions.

use bitcoin_hashes as hashes;
use bitcoin_hashes::{Hash, HashEngine};

/// Computes a one-off SHA256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    hashes::sha256::Hash::hash(data).to_byte_array()
}

/// Computes a one-off RIPEMD160 hash.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    hashes::ripemd160::Hash::hash(data).to_byte_array()
}

/// Allows the computation of a SHA256 hash using multiple updates.
#[derive(Default)]
pub struct Sha256Engine(hashes::sha256::HashEngine);

impl Sha256Engine {
    /// Updates the engine with data.
    pub fn update(&mut self, data: &[u8]) {
        self.0.input(data);
    }

    /// Consumes the engine and returns the hash.
    pub fn finalize(self) -> [u8; 32] {
        hashes::sha256::Hash::from_engine(self.0).to_byte_array()
    }
}

/// Decodes a B58 encoded xpub and returns the inner public key.
pub fn decode_xpub(xpub: &str) -> Option<k256::PublicKey> {
    use base58::FromBase58;
    let decoded_xpub = xpub.from_base58().ok()?;
    k256::PublicKey::from_sec1_bytes(&decoded_xpub[45..45 + 33]).ok()
}

/// Calculates the fingerprint of a public key per BIP32.
pub fn xfp(pk: &k256::PublicKey) -> [u8; 4] {
    let hash = ripemd160(&sha256(&pk.to_sec1_bytes()));
    hash.as_slice()[..4].try_into().expect("cannot fail")
}

/// Wraps an instance that's either owned or borrowed.
pub enum MaybeOwned<'a, T> {
    Owned(T),
    Borrowed(&'a mut T),
}

impl<T> AsRef<T> for MaybeOwned<'_, T> {
    fn as_ref(&self) -> &T {
        match self {
            MaybeOwned::Owned(owned) => owned,
            MaybeOwned::Borrowed(borrowed) => borrowed,
        }
    }
}

impl<T> AsMut<T> for MaybeOwned<'_, T> {
    fn as_mut(&mut self) -> &mut T {
        match self {
            MaybeOwned::Owned(owned) => owned,
            MaybeOwned::Borrowed(borrowed) => borrowed,
        }
    }
}

pub fn parse_string_vec(response: &str) -> Vec<String> {
    // expected input kind: ["Liana-rkkrtqy6", "Liana-947xsd0w"]
    let resp = response.replace("\"", "");
    let end = resp.len() - 1;
    let resp = resp[1..end].to_string();
    resp.split(",").map(|s| s.trim().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_string_vec() {
        // 2 entries
        let response = "[\"Liana-rkkrtqy6\", \"Liana-947xsd0w\"]";
        let parsed = parse_string_vec(response);
        assert_eq!(parsed, vec!["Liana-rkkrtqy6", "Liana-947xsd0w"]);

        // 1 entry
        let response = "[\"solo\"]";
        let parsed = parse_string_vec(response);
        assert_eq!(parsed, vec!["solo"]);

        // empty entry
        let response = "[]";
        let parsed = parse_string_vec(response);
        assert_eq!(parsed, vec![""]);
    }
}
