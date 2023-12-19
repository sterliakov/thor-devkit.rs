//! VeChain address operations and verifications.

use crate::utils::keccak;
use alloy_rlp::{Decodable, Encodable};
use ethereum_types::Address as WrappedAddress;
pub use secp256k1::{PublicKey, SecretKey as PrivateKey};
use std::{
    ops::{Deref, DerefMut},
    result::Result,
    str::FromStr,
};

/// VeChain address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Address(WrappedAddress);

impl DerefMut for Address {
    // type Target = WrappedAddress;

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
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        use crate::transactions::lstrip;
        alloy_rlp::Bytes::copy_from_slice(&lstrip(self.0)).encode(out)
    }
}
impl Decodable for Address {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        use crate::transactions::static_left_pad;
        let bytes = alloy_rlp::Bytes::decode(buf)?;
        Ok(Self(WrappedAddress::from_slice(
            &static_left_pad::<20>(&bytes).map_err(|e| match e {
                alloy_rlp::Error::Overflow => alloy_rlp::Error::ListLengthMismatch {
                    expected: Self::WIDTH,
                    got: bytes.len(),
                },
                e => e,
            })?,
        )))
    }
}
impl FromStr for Address {
    type Err = rustc_hex::FromHexError;

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

    pub fn to_checksum_address(&self) -> String {
        //! Create a checksum address

        let body = format!("{:02x?}", self.0);
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

/// Invalid public key format reasons
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressValidationError {
    /// Not of length 20
    InvalidLength,
    /// Not a hex string
    InvalidHex,
}
