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

#[cfg(feature = "serde")]
pub(crate) mod unhex {
    use rustc_hex::{FromHex, ToHex};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_with::de::DeserializeAs;
    use serde_with::formats::{Format, Lowercase, Uppercase};
    use serde_with::ser::SerializeAs;
    use std::borrow::Cow;
    use std::convert::{TryFrom, TryInto};
    use std::marker::PhantomData;

    #[derive(Copy, Clone, Debug, Default)]
    pub struct Hex<FORMAT: Format = Lowercase>(PhantomData<FORMAT>);

    impl<T: ToHex> SerializeAs<T> for Hex<Lowercase> {
        fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&("0x".to_string() + &source.to_hex::<String>()))
        }
    }

    impl<T: ToHex> SerializeAs<T> for Hex<Uppercase> {
        fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer
                .serialize_str(&("0x".to_string() + &source.to_hex::<String>().to_uppercase()))
        }
    }

    impl<'de, T, FORMAT> DeserializeAs<'de, T> for Hex<FORMAT>
    where
        T: TryFrom<Vec<u8>>,
        FORMAT: Format,
    {
        fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
            <Cow<'de, str> as Deserialize<'de>>::deserialize(deserializer)
                .and_then(|s| {
                    s.strip_prefix("0x").unwrap_or(&s).from_hex().map_err(|e| {
                        println!("{:?}", e);
                        Error::custom(e)
                    })
                })
                .and_then(|vec: Vec<u8>| {
                    let length = vec.len();
                    vec.try_into().map_err(|_e: T::Error| {
                        Error::custom(format!(
                            "Can't convert a Byte Vector of length {} to the output type.",
                            length
                        ))
                    })
                })
        }
    }
}
