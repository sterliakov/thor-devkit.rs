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
