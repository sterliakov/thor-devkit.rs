//! VeChain address operations and verifications.

use crate::rlp::{Decodable, Encodable, RLPError};
use crate::utils::keccak;
use alloy::primitives::Address as WrappedAddress;
pub use const_hex::FromHexError as AddressValidationError;
pub use secp256k1::{PublicKey, SecretKey as PrivateKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

/// VeChain address.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Address(WrappedAddress);

impl DerefMut for Address {
    fn deref_mut(&mut self) -> &mut WrappedAddress {
        &mut self.0
    }
}
impl Deref for Address {
    type Target = WrappedAddress;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Encodable for Address {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        self.0.encode(out)
    }
}
impl Decodable for Address {
    fn decode(buf: &mut &[u8]) -> Result<Self, RLPError> {
        Ok(Self(WrappedAddress::decode(buf)?))
    }
}
impl FromStr for Address {
    type Err = AddressValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(WrappedAddress::from_str(s)?))
    }
}
impl<T: Into<WrappedAddress>> From<T> for Address {
    fn from(s: T) -> Self {
        Self(s.into())
    }
}

impl Address {
    /// Size of underlying array in bytes.
    pub const WIDTH: usize = 20;

    pub fn to_hex(&self) -> String {
        //! Encode as a hex string with `0x` prefix.
        format!("{:02x?}", self.0)
    }

    pub fn to_checksum_address(&self) -> String {
        //! Create a checksum address

        let body = self.to_hex();
        let hash = keccak(&body.clone()[2..42]);

        "0x".chars()
            .chain(
                body.chars()
                    .skip(2)
                    .zip(itertools::interleave(
                        hash.iter().map(|x| x >> 4),
                        hash.iter().map(|x| x & 15),
                    ))
                    .map(|(ch, h)| if h >= 8 { ch.to_ascii_uppercase() } else { ch }),
            )
            .collect()
    }
}

/// A trait for objects that can generate an on-chain address.
pub trait AddressConvertible {
    /// Create an address
    fn address(&self) -> Address;
}

impl AddressConvertible for secp256k1::PublicKey {
    fn address(&self) -> Address {
        //! Generate address from public key.
        // Get rid of the 0x04 (first byte) at the beginning.
        let hash = keccak(&self.serialize_uncompressed()[1..]);
        // last 20 bytes from the 32 bytes hash.
        let suffix: [u8; 20] = hash[12..32].try_into().expect("Preset slice length");
        Address(WrappedAddress::from_slice(&suffix))
    }
}
