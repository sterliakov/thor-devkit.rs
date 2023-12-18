//! VeChain address operations and verifications.

use alloy_rlp::{RlpDecodableWrapper, RlpEncodableWrapper};
pub use secp256k1::{PublicKey, SecretKey as PrivateKey};
use std::fmt;
use std::result::Result;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

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

/// Represents VeChain address
#[derive(Eq, PartialEq, Clone, Copy, Debug, RlpDecodableWrapper, RlpEncodableWrapper)]
pub struct Address([u8; 20]);

impl FromStr for Address {
    type Err = AddressValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let addr = decode_hex(value)?;
        addr.try_into()
    }
}
impl TryFrom<&[u8]> for Address {
    type Error = AddressValidationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let addr: [u8; 20] = value
            .try_into()
            .map_err(|_| AddressValidationError::InvalidLength {})?;
        Ok(Address(addr))
    }
}
impl TryFrom<Vec<u8>> for Address {
    type Error = AddressValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Address {
    pub fn to_checksum_address(&self) -> String {
        //! Create a checksum address

        let body = self.to_string();
        let mut hasher = Keccak::v256();
        hasher.update(&body.clone().into_bytes()[2..42]);
        let mut hash = [0; 32];
        hasher.finalize(&mut hash);

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
    /// Get raw underlying bytes
    pub fn to_bytes(self) -> [u8; 20] {
        self.0
    }
}

/// A trait for objects that can generate an on-chain address.
pub trait AddressConvertible {
    /// Create an address
    fn address(&self) -> Address;
}

// TODO: add VerifyingKey from the same crate

impl AddressConvertible for secp256k1::PublicKey {
    fn address(&self) -> Address {
        //! Generate address from public key.
        // Get rid of the 0x04 (first byte) at the beginning.
        let mut hasher = Keccak::v256();
        hasher.update(&self.serialize_uncompressed()[1..]);
        let mut hash = [0; 32];
        hasher.finalize(&mut hash);
        // last 20 bytes from the 32 bytes hash.
        Address(hash[12..32].try_into().unwrap())
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
    use crate::address::{Address, AddressConvertible, AddressValidationError, PublicKey};

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
        ];

        addresses.into_iter().for_each(|addr| {
            assert_eq!(addr, addr.parse::<Address>().unwrap().to_checksum_address());
        })
    }

    #[test]
    fn test_invalid_address() {
        assert_eq!(
            AddressValidationError::InvalidLength,
            "".parse::<Address>().unwrap_err()
        );
        assert_eq!(
            AddressValidationError::InvalidLength,
            "0x".parse::<Address>().unwrap_err()
        );
        assert_eq!(
            AddressValidationError::InvalidLength,
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aD"
                .parse::<Address>()
                .unwrap_err()
        );
        assert_eq!(
            AddressValidationError::InvalidLength,
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9a"
                .parse::<Address>()
                .unwrap_err()
        );
        assert_eq!(
            AddressValidationError::InvalidHex,
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aGG"
                .parse::<Address>()
                .unwrap_err()
        );
    }
}
