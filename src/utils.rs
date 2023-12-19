use crate::address::AddressValidationError;
use blake2::{digest::consts::U32, Blake2b, Digest};
use tiny_keccak::{Hasher, Keccak};

type Blake2b256 = Blake2b<U32>;

pub fn blake2_256<S: AsRef<[u8]>>(bytes: &[S]) -> [u8; 32] {
    //! Compute blake2b hash with 32-byte digest.
    //!
    //! Builds a hash iteratively by updating with every element
    //! of the input sequence.
    let mut hasher = Blake2b256::new();
    bytes.iter().for_each(|b| hasher.update(b));
    hasher.finalize().try_into().unwrap()
}

pub fn keccak<S: AsRef<[u8]>>(bytes: S) -> [u8; 32] {
    //! Compute a keccak hash with 32-byte digest.
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    let mut hash = [0; 32];
    hasher.finalize(&mut hash);
    hash
}

#[cfg(not(tarpaulin_include))]
pub fn decode_hex(s: &str) -> Result<Vec<u8>, AddressValidationError> {
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
