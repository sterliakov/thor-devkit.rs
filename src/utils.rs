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
    hasher.finalize().into()
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
    use crate::U256;
    use rustc_hex::{FromHex, ToHex};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_with::de::DeserializeAs;
    use serde_with::formats::{Format, Lowercase, Uppercase};
    use serde_with::ser::SerializeAs;
    use std::any::type_name;
    use std::borrow::Cow;
    use std::marker::PhantomData;

    #[derive(Copy, Clone, Debug, Default)]
    pub struct Hex<FORMAT: Format = Lowercase>(PhantomData<FORMAT>);

    impl<T: AsRef<[u8]>> SerializeAs<T> for Hex<Lowercase> {
        fn serialize_as<S: Serializer>(source: &T, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&("0x".to_string() + &source.as_ref().to_hex::<String>()))
        }
    }

    impl<T: AsRef<[u8]>> SerializeAs<T> for Hex<Uppercase> {
        fn serialize_as<S: Serializer>(source: &T, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(
                &("0x".to_string() + &source.as_ref().to_hex::<String>().to_uppercase()),
            )
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
                    s.strip_prefix("0x")
                        .unwrap_or(&s)
                        .from_hex()
                        .map_err(Error::custom)
                })
                .and_then(|vec: Vec<u8>| {
                    let length = vec.len();
                    vec.try_into().map_err(|_e: T::Error| {
                        Error::custom(format!(
                            "Can't convert a Byte Vector of length {} to {}",
                            length,
                            type_name::<T>(),
                        ))
                    })
                })
        }
    }

    pub trait BeBytesConvertible<const N: usize>
    where
        Self: Sized,
    {
        fn from_be_bytes(src: [u8; N]) -> Self;
        fn to_be_bytes_(self) -> [u8; N];
    }

    macro_rules! impl_from_be_bytes {
        ($t:ty) => {
            impl BeBytesConvertible<{ <$t>::BITS as usize / 8 }> for $t {
                fn from_be_bytes(src: [u8; <$t>::BITS as usize / 8]) -> Self {
                    Self::from_be_bytes(src)
                }
                fn to_be_bytes_(self) -> [u8; <$t>::BITS as usize / 8] {
                    self.to_be_bytes()
                }
            }
        };
    }
    impl_from_be_bytes!(u64);
    impl_from_be_bytes!(u32);
    impl_from_be_bytes!(u16);
    impl BeBytesConvertible<32> for U256 {
        fn from_be_bytes(src: [u8; 32]) -> Self {
            Self::from_big_endian(&src)
        }
        fn to_be_bytes_(self) -> [u8; 32] {
            let mut buf = [0; 32];
            self.to_big_endian(&mut buf);
            buf
        }
    }

    impl BeBytesConvertible<1> for u8 {
        fn from_be_bytes(src: [u8; 1]) -> Self {
            src[0]
        }
        fn to_be_bytes_(self) -> [u8; 1] {
            [self]
        }
    }

    #[derive(Copy, Clone, Debug, Default)]
    pub struct HexNum<const N: usize, Type: BeBytesConvertible<N>, FORMAT: Format = Lowercase>(
        PhantomData<Type>,
        PhantomData<FORMAT>,
    );

    impl<const N: usize, T: Copy + BeBytesConvertible<N>> SerializeAs<T> for HexNum<N, T, Lowercase> {
        fn serialize_as<S: Serializer>(source: &T, serializer: S) -> Result<S::Ok, S::Error> {
            serializer
                .serialize_str(&("0x".to_string() + &source.to_be_bytes_().to_hex::<String>()))
        }
    }

    impl<const N: usize, T: Copy + BeBytesConvertible<N>> SerializeAs<T> for HexNum<N, T, Uppercase> {
        fn serialize_as<S: Serializer>(source: &T, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(
                &("0x".to_string() + &source.to_be_bytes_().to_hex::<String>().to_uppercase()),
            )
        }
    }

    impl<'de, const N: usize, Type: BeBytesConvertible<N>, T, FORMAT> DeserializeAs<'de, T>
        for HexNum<N, Type, FORMAT>
    where
        T: From<Type>,
        FORMAT: Format,
    {
        fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
            <Cow<'de, str> as Deserialize<'de>>::deserialize(deserializer)
                .and_then(|s| {
                    let stripped = s.strip_prefix("0x").unwrap_or(&s);
                    let padded = if stripped.len() % 2 == 0 {
                        stripped.to_string()
                    } else {
                        "0".to_string() + stripped
                    };
                    padded.from_hex().map_err(Error::custom)
                })
                .and_then(|vec: Vec<u8>| {
                    let length = vec.len();
                    Ok(Type::from_be_bytes(static_left_pad::<N>(&vec).map_err(|_| {
                        Error::custom(format!(
                            "Can't convert a Byte Vector of length {} to {}",
                            length,
                            type_name::<Type>(),
                        ))
                    })?)
                    .into())
                })
        }
    }

    #[inline]
    #[cfg(not(tarpaulin_include))]
    fn static_left_pad<const N: usize>(data: &[u8]) -> Result<[u8; N], open_fastrlp::DecodeError> {
        // Similar to RLP padding, but allows leading zero. Tested there.
        if data.len() > N {
            return Err(open_fastrlp::DecodeError::Overflow);
        }

        let mut v = [0; N];

        if data.is_empty() {
            return Ok(v);
        }

        // SAFETY: length checked above
        unsafe { v.get_unchecked_mut(N - data.len()..) }.copy_from_slice(data);
        Ok(v)
    }
}

#[cfg(feature = "serde")]
#[cfg(test)]
mod test {
    use super::super::rlp::Bytes;
    use super::super::U256;
    use super::unhex::*;
    use serde::{Deserialize, Serialize};
    use serde_json::{from_str, json, to_value};
    use serde_with::formats::{Lowercase, Uppercase};

    #[test]
    fn test_numbers() {
        #[serde_with::serde_as]
        #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
        struct Test {
            #[serde_as(as = "HexNum<1, u8>")]
            a: u8,
            #[serde_as(as = "HexNum<2, u16>")]
            b: u16,
            #[serde_as(as = "HexNum<4, u32>")]
            c: u32,
            #[serde_as(as = "HexNum<8, u64>")]
            d: u64,
            #[serde_as(as = "HexNum<32, U256>")]
            e: U256,
        }
        assert_eq!(
            to_value(Test {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                e: 0.into()
            })
            .expect("Works"),
            json! {{
                "a": "0x00",
                "b": "0x0000",
                "c": "0x00000000",
                "d": "0x0000000000000000",
                "e": "0x0000000000000000000000000000000000000000000000000000000000000000",
            }}
        );
        assert_eq!(
            from_str::<Test>(
                r#"{
                "a": "0x00",
                "b": "0x0000",
                "c": "0x00000000",
                "d": "0x0000000000000000",
                "e": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }"#
            )
            .expect("Must parse"),
            Test {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                e: 0.into()
            },
        );
    }

    #[test]
    fn test_numbers_padding() {
        #[serde_with::serde_as]
        #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
        struct Test {
            #[serde_as(as = "HexNum<2, u16>")]
            a: u16,
        }
        assert_eq!(
            from_str::<Test>(r#"{"a": "0x1"}"#).expect("Must parse"),
            Test { a: 1_u16 },
        );
    }

    #[test]
    fn test_numbers_fail_too_long() {
        #[serde_with::serde_as]
        #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
        struct Test {
            #[serde_as(as = "HexNum<2, u16>")]
            a: u16,
        }
        assert_eq!(
            from_str::<Test>(r#"{"a": "0x01010101"}"#)
                .expect_err("Must not parse")
                .to_string(),
            "Can't convert a Byte Vector of length 4 to u16 at line 1 column 19"
        );
    }

    #[test]
    fn test_wrapped_numbers() {
        #[serde_with::serde_as]
        #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
        struct Test {
            #[serde_as(as = "Option<HexNum<1, u8, Uppercase>>")]
            a: Option<u8>,
            #[serde_as(as = "Option<HexNum<1, u8>>")]
            b: Option<u8>,
            #[serde_as(as = "Vec<HexNum<2, u16, Lowercase>>")]
            c: Vec<u16>,
        }
        assert_eq!(
            to_value(Test {
                a: Some(0x0F),
                b: None,
                c: vec![1, 0x0E],
            })
            .expect("Works"),
            json! {{
                "a": "0x0F",
                "b": Option::<u8>::None,
                "c": vec!["0x0001", "0x000e"],
            }}
        );
        assert_eq!(
            from_str::<Test>(
                r#"{
                "a": "0x0f",
                "b": null,
                "c": ["0x0001", "0x000E"]
            }"#
            )
            .expect("Must parse"),
            Test {
                a: Some(0x0F),
                b: None,
                c: vec![1, 0x0E],
            }
        );
    }

    #[test]
    fn test_hex_strings() {
        #[serde_with::serde_as]
        #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
        struct Test {
            #[serde_as(as = "Option<Hex>")]
            a: Option<Vec<u8>>,
            #[serde_as(as = "Option<Hex<Lowercase>>")]
            b: Option<Bytes>,
            #[serde_as(as = "Option<Hex<Lowercase>>")]
            c: Option<Bytes>,
            #[serde_as(as = "Vec<Hex<Uppercase>>")]
            d: Vec<Bytes>,
            #[serde_as(as = "Vec<Hex<Uppercase>>")]
            e: Vec<Bytes>,
            #[serde_as(as = "Vec<Hex<Lowercase>>")]
            f: Vec<Bytes>,
        }
        assert_eq!(
            to_value(Test {
                a: Some(vec![]),
                b: None,
                c: Some(Bytes::copy_from_slice(&b"\x01\x0F"[..])),
                d: vec![Bytes::copy_from_slice(&b"\x01\x0F"[..])],
                e: vec![],
                f: vec![Bytes::copy_from_slice(&b"\x01\x0F"[..])],
            })
            .expect("Works"),
            json! {{
                "a": "0x",
                "b": Option::<u8>::None,
                "c": "0x010f",
                "d": vec!["0x010F"],
                "e": Vec::<u8>::new(),
                "f": vec!["0x010f"]
            }}
        );
        assert_eq!(
            from_str::<Test>(
                r#"{
                "a": "0x",
                "b": null,
                "c": "0x010f",
                "d": ["0x010F"],
                "e": [],
                "f": ["0x010f"]
            }"#
            )
            .expect("Must parse"),
            Test {
                a: Some(vec![]),
                b: None,
                c: Some(Bytes::copy_from_slice(&b"\x01\x0F"[..])),
                d: vec![Bytes::copy_from_slice(&b"\x01\x0F"[..])],
                e: vec![],
                f: vec![Bytes::copy_from_slice(&b"\x01\x0F"[..])],
            }
        );
    }

    #[test]
    fn test_string_fail_too_long() {
        #[serde_with::serde_as]
        #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
        struct Test {
            #[serde_as(as = "Hex")]
            a: [u8; 3],
        }
        assert_eq!(
            from_str::<Test>(r#"{"a": "0x01010101"}"#)
                .expect_err("Must not parse")
                .to_string(),
            "Can't convert a Byte Vector of length 4 to [u8; 3] at line 1 column 19"
        );
    }

    #[test]
    fn test_string_fail_too_short() {
        #[serde_with::serde_as]
        #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
        struct Test {
            #[serde_as(as = "Hex")]
            a: [u8; 5],
        }
        assert_eq!(
            from_str::<Test>(r#"{"a": "0x01010101"}"#)
                .expect_err("Must not parse")
                .to_string(),
            "Can't convert a Byte Vector of length 4 to [u8; 5] at line 1 column 19"
        );
    }

    #[test]
    fn test_string_fail_bad_hex() {
        #[serde_with::serde_as]
        #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
        struct Test {
            #[serde_as(as = "Hex")]
            a: [u8; 5],
        }
        assert_eq!(
            from_str::<Test>(r#"{"a": "0x0101010G"}"#)
                .expect_err("Must not parse")
                .to_string(),
            "Invalid character 'G' at position 7 at line 1 column 19"
        );
    }
}
