//! Miscellaneous utility functions.
use bitcoin::hashes;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1;

/// Computes a one-off SHA256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    hashes::sha256::Hash::hash(data).into_inner()
}

/// Computes a one-off RIPEMD160 hash.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    hashes::ripemd160::Hash::hash(data).into_inner()
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
        hashes::sha256::Hash::from_engine(self.0).into_inner()
    }
}

/// Decodes a B58 encoded xpub and returns the inner public key.
pub fn decode_xpub(xpub: &str) -> Option<secp256k1::PublicKey> {
    let decoded_xpub = bitcoin::util::base58::from(xpub).ok()?;
    secp256k1::PublicKey::from_slice(&decoded_xpub[45..45 + 33]).ok()
}

/// Calculates the fingerprint of a public key per BIP32.
pub fn xfp(pk: &secp256k1::PublicKey) -> [u8; 4] {
    let hash = ripemd160(&sha256(&pk.serialize()));
    hash.as_slice()[..4].try_into().expect("cannot fail")
}
