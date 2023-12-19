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

#[cfg(test)]
pub(crate) fn decode_hex(s: &str) -> Result<Vec<u8>, AddressValidationError> {
    //! Convert a hex string (with or without 0x prefix) to binary.
    let prefix = if s.starts_with("0x") { 2 } else { 0 };
    (0..s.len())
        .skip(prefix)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(
                s.get(i..i + 2)
                    .ok_or(AddressValidationError::InvalidLength)?,
                16,
            )
            .map_err(|_| AddressValidationError::InvalidHex)
        })
        .collect()
}

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

#[cfg(test)]
mod tests {
    use crate::address::*;

    #[test]
    fn test_upubkey_to_address() {
        let pubkey: PublicKey = (
            "04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f"
        ).parse().unwrap();
        let ref_addr: Address = "d989829d88b0ed1b06edf5c50174ecfa64f14a64".parse().unwrap();
        assert_eq!(pubkey.address(), ref_addr);
    }

    #[test]
    fn test_pubkey_to_address() {
        let pubkey: PublicKey =
            "03c1573f1528638ae14cbe04a74e6583c5562d59214223762c1a11121e24619cbc"
                .parse()
                .unwrap();
        let ref_addr: Address = "Af3CD5c36B97E9c28c263dC4639c6d7d53303A13".parse().unwrap();
        assert_eq!(pubkey.address(), ref_addr);
    }

    #[test]
    fn test_to_checksum_address() {
        let addresses = vec![
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            "0x00220a0cf47C7B9Be7a2e6ba89f429762e7B9adB",
        ];

        addresses.iter().for_each(|&addr| {
            assert_eq!(addr, addr.parse::<Address>().unwrap().to_checksum_address());
        });
        addresses.iter().for_each(|&addr| {
            assert_eq!(
                addr,
                addr.to_lowercase()
                    .parse::<Address>()
                    .unwrap()
                    .to_checksum_address()
            );
        });
    }
}
