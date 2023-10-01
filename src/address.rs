//! VeChain "public key" and "address" related operations and verifications.

use keccak_hash::keccak;
use secp256k1::{Parity, PublicKey as RawPublicKey, XOnlyPublicKey};
use std::num::ParseIntError;
use std::result::Result;
use std::str::FromStr;
use std::{fmt, unreachable};

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    //! Convert a hex string (with or without 0x prefix) to binary.
    let prefix = if s.starts_with("0x") { 2 } else { 0 };
    (0..s.len())
        .skip(prefix)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

/// Represents VeChain address
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct Address([u8; 20]);
impl FromStr for Address {
    type Err = AddressValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let addr = decode_hex(value).map_err(|_| AddressValidationError::InvalidHex {})?;
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

impl From<UncompressedPublicKey> for Address {
    fn from(key: UncompressedPublicKey) -> Self {
        key.to_address()
    }
}
impl From<PublicKey> for Address {
    fn from(key: PublicKey) -> Self {
        key.to_address()
    }
}

impl Address {
    pub fn to_checksum_address(&self) -> String {
        //! Create a checksum address

        let body = self.to_string();
        let hash = keccak(&body.clone().into_bytes()[2..42]).to_fixed_bytes();

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

/// Represents VeChain uncompressed public key
///
/// Likely you will never need this API, uncompressed pubkeys
/// are considered legacy and rarely used.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct UncompressedPublicKey([u8; 65]);
impl FromStr for UncompressedPublicKey {
    type Err = KeyValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let addr = decode_hex(value).map_err(|_| KeyValidationError::InvalidHex {})?;
        addr.try_into()
    }
}
impl TryFrom<&[u8]> for UncompressedPublicKey {
    type Error = KeyValidationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let addr: [u8; 65] = value
            .try_into()
            .map_err(|_| KeyValidationError::InvalidLength {})?;
        if addr[0] == 0x04 {
            Ok(UncompressedPublicKey(addr))
        } else {
            Err(KeyValidationError::InvalidStartByte {})
        }
    }
}
impl TryFrom<Vec<u8>> for UncompressedPublicKey {
    type Error = KeyValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}
impl fmt::Display for UncompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
impl UncompressedPublicKey {
    pub fn to_address(&self) -> Address {
        //! Generate address from public key.
        // Get rid of the 0x04 (first byte) at the beginning.
        let hash = keccak(&self.0[1..]).to_fixed_bytes();
        // last 20 bytes from the 32 bytes hash.
        Address(hash[12..32].try_into().unwrap())
    }
    pub fn to_compressed(&self) -> PublicKey {
        //! Convert to compressed (shorter) format.
        let public_key = RawPublicKey::from_slice(&self.0).unwrap();
        PublicKey(public_key.serialize())
    }
    /// Get raw underlying bytes
    pub fn to_bytes(self) -> [u8; 65] {
        self.0
    }
}

/// Represents VeChain compressed public key
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct PublicKey([u8; 33]);
impl FromStr for PublicKey {
    type Err = KeyValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let addr = decode_hex(value).map_err(|_| KeyValidationError::InvalidHex {})?;
        addr.try_into()
    }
}
impl TryFrom<&[u8]> for PublicKey {
    type Error = KeyValidationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let addr: [u8; 33] = value
            .try_into()
            .map_err(|_| KeyValidationError::InvalidLength {})?;
        if addr[0] == 0x03 || addr[0] == 0x02 {
            Ok(PublicKey(addr))
        } else {
            Err(KeyValidationError::InvalidStartByte {})
        }
    }
}
impl TryFrom<Vec<u8>> for PublicKey {
    type Error = KeyValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
impl PublicKey {
    pub fn to_address(&self) -> Address {
        //! Generate address from public key.
        //!
        //! VeChain uses addresses generated from uncompressed pubkeys
        self.to_uncompressed().to_address()
    }
    pub fn to_uncompressed(&self) -> UncompressedPublicKey {
        //! Convert to uncompressed (longer) format.
        let public_key = XOnlyPublicKey::from_slice(&self.0[1..]).unwrap();
        let parity = match self.0[0] {
            0x02 => Parity::Even,
            0x03 => Parity::Odd,
            _ => unreachable!(),
        };
        UncompressedPublicKey(public_key.public_key(parity).serialize_uncompressed())
    }
    /// Get raw underlying bytes
    pub fn to_bytes(self) -> [u8; 33] {
        self.0
    }
}

/// Invalid public key format reasons
#[derive(Debug)]
pub enum AddressValidationError {
    /// Not of length 20
    InvalidLength,
    /// Not a hex string
    InvalidHex,
}
/// Invalid public key format reasons
#[derive(Debug)]
pub enum KeyValidationError {
    /// Not a hex string
    InvalidHex,
    /// Not of length 65
    InvalidLength,
    /// Does not start with 0x04 (uncompressed) or 0x02/0x03 (compressed)
    InvalidStartByte,
}

#[cfg(test)]
mod tests {
    use crate::address::{Address, PublicKey, UncompressedPublicKey};

    #[test]
    fn test_upubkey_to_address() {
        let pubkey: UncompressedPublicKey = (
            "04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f"
        ).parse().unwrap();
        let ref_addr: Address = "d989829d88b0ed1b06edf5c50174ecfa64f14a64".parse().unwrap();
        assert_eq!(pubkey.to_address(), ref_addr);
    }

    #[test]
    fn test_pubkey_to_address() {
        let pubkey: PublicKey =
            ("03c1573f1528638ae14cbe04a74e6583c5562d59214223762c1a11121e24619cbc")
                .parse()
                .unwrap();
        let ref_addr: Address = "Af3CD5c36B97E9c28c263dC4639c6d7d53303A13".parse().unwrap();
        assert_eq!(pubkey.to_address(), ref_addr);
    }

    #[test]
    fn test_pubkey_to_upubkey() {
        let pubkey: PublicKey =
            ("03b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304a")
                .parse()
                .unwrap();
        let uncompressed: UncompressedPublicKey = (
            "04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f"
        ).parse().unwrap();
        assert_eq!(pubkey, uncompressed.to_compressed());
        assert_eq!(pubkey.to_uncompressed(), uncompressed);
        assert_eq!(
            pubkey.to_address(),
            uncompressed.to_address(),
            "Addresses must match"
        );
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
}
