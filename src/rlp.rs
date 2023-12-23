//! This module enables RLP encoding of high-level objects.
//!
//! RLP (recursive length prefix) is a common algorithm for encoding
//! of variable length binary data. RLP encodes data before storing on disk
//! or transmitting via network.
//!
//! Theory
//! ------
//!
//! Encoding
//! ********
//!
//! Primary RLP can only deal with "item" type, which is defined as:
//!
//! - Byte string ([`Bytes`]) or
//! - Sequence of items ([`Vec`], fixed array or slice).
//!
//! Some examples are:
//!
//! * ``b'\x00\xff'``
//! * empty list ``vec![]``
//! * list of bytes ``vec![vec![0u8], vec![1u8, 3u8]]``
//! * list of combinations ``vec![vec![], vec![0u8], vec![vec![0]]]``
//!
//! The encoded result is always a byte string (sequence of [`u8`]).
//!
//! Encoding algorithm
//! ******************
//!
//! Given `x` item as input, we define `rlp_encode` as the following algorithm:
//!
//! Let `concat` be a function that joins given bytes into single byte sequence.
//! 1. If `x` is a single byte and `0x00 <= x <= 0x7F`, `rlp_encode(x) = x`.
//! 1. Otherwise, if `x` is a byte string, let `len(x)` be length of `x` in bytes
//!    and define encoding as follows:
//!    * If `0 < len(x) < 0x38` (note that empty byte string fulfills this requirement), then
//!      ```txt
//!      rlp_encode(x) = concat(0x80 + len(x), x)
//!      ```
//!      In this case first byte is in range `[0x80; 0xB7]`.
//!    * If `0x38 <= len(x) <= 0xFFFFFFFF`, then
//!      ```txt
//!      rlp_encode(x) = concat(0xB7 + len(len(x)), len(x), x)
//!      ```
//!      In this case first byte is in range `[0xB8; 0xBF]`.
//!    * For longer strings encoding is undefined.
//! 1. Otherwise, if `x` is a list, let `s = concat(map(rlp_encode, x))`
//!    be concatenation of RLP encodings of all its items.
//!    * If `0 < len(s) < 0x38` (note that empty list matches), then
//!      ```txt
//!      rlp_encode(x) = concat(0xC0 + len(s), s)
//!      ```
//!      In this case first byte is in range `[0xC0; 0xF7]`.
//!    * If `0x38 <= len(s) <= 0xFFFFFFFF`, then
//!      ```txt
//!      rlp_encode(x) = concat(0xF7 + len(len(s)), len(s), x)
//!      ```
//!      In this case first byte is in range `[0xF8; 0xFF]`.
//!    * For longer lists encoding is undefined.
//!
//! See more in [Ethereum wiki](https://eth.wiki/fundamentals/rlp).
//!
//! Encoding examples
//! *****************
//!
//! | ``x``             |       ``rlp_encode(x)``        |
//! |-------------------|--------------------------------|
//! | ``b''``           | ``0x80``                       |
//! | ``b'\x00'``       | ``0x00``                       |
//! | ``b'\x0F'``       | ``0x0F``                       |
//! | ``b'\x79'``       | ``0x79``                       |
//! | ``b'\x80'``       | ``0x81 0x80``                  |
//! | ``b'\xFF'``       | ``0x81 0xFF``                  |
//! | ``b'foo'``        | ``0x83 0x66 0x6F 0x6F``        |
//! | ``[]``            | ``0xC0``                       |
//! | ``[b'\x0F']``     | ``0xC1 0x0F``                  |
//! | ``[b'\xEF']``     | ``0xC1 0x81 0xEF``             |
//! | ``[[], [[]]]``    | ``0xC3 0xC0 0xC1 0xC0``        |
//!
//!
//! Serialization
//! *************
//!
//! However, in the real world, the inputs are not pure bytes nor lists.
//! We need a way to encode numbers (like [`u64`]), custom structs, enums and other
//! more complex machinery that exists in the surrounding code.
//!
//! This library wraps [`open_fastrlp`](https://docs.rs/open-fastrlp/0.1.4/open_fastrlp/)
//! crate, so everything mentioned there about [`Encodable`] and [`Decodable`] traits still
//! applies. You can implement those for any object to make it RLP-serializable.
//!
//! However, following this approach directly results in cluttered code: your `struct`s
//! now have to use field types that match serialization, which may be very inconvenient.
//!
//! To avoid this pitfall, this RLP implementation allows "extended" struct definition
//! via a macro. Let's have a look at `Transaction` definition:
//!
//! ```rust
//! use thor_devkit::rlp::{AsBytes, AsVec, Maybe, Bytes};
//! use thor_devkit::{rlp_encodable, U256};
//! use thor_devkit::transactions::{Clause, Reserved};
//!
//! rlp_encodable! {
//!     /// Represents a single VeChain transaction.
//!     #[derive(Clone, Debug, Eq, PartialEq)]
//!     pub struct Transaction {
//!         /// Chain tag
//!         pub chain_tag: u8,
//!         pub block_ref: u64,
//!         pub expiration: u32,
//!         pub clauses: Vec<Clause>,
//!         pub gas_price_coef: u8,
//!         pub gas: u64,
//!         pub depends_on: Option<U256> => AsBytes<U256>,
//!         pub nonce: u64,
//!         pub reserved: Option<Reserved> => AsVec<Reserved>,
//!         pub signature: Option<Bytes> => Maybe<Bytes>,
//!     }
//! }
//! ```
//!
//! What's going on here? First, some fields are encoded "as usual": unsigned integers
//! are encoded just fine and you likely won't need any different encoding. However,
//! some fields work in a different way. `depends_on` is a number that may be present
//! or absent, and it should be encoded as a byte sting. `U256` is already encoded this
//! way, but `None` is not ([`Option`] is not RLP-serializable on itself). So we wrap it
//! in a special wrapper: [`AsBytes`]. [`AsBytes<T>`] will serialize `Some(T)` as `T` and
//! [`None`] as an empty byte string.
//!
//! `reserved` is a truly special struct that has custom encoding implemented for it.
//! That implementation serializes `Reserved` into a [`Vec<Bytes>`], and then serializes
//! this [`Vec<Bytes>`] to the output stream. If it is empty, an empty vector should be
//! written instead. This is achieved via [`AsVec`] annotation.
//!
//! [`Maybe`] is a third special wrapper. Fields annotated with [`Maybe`] may only be placed
//! last (otherwise encoding is ambiguous), and with [`Maybe<T>`] `Some(T)` is serialized
//! as `T` and [`None`] --- as nothing (zero bytes added).
//!
//! Fields comments are omitted here for brevity, they are preserved as well.
//!
//! This macro adds both decoding and encoding capabilities. See examples folder
//! for more examples of usage, including custom types and machinery.
//!
//! Note that this syntax is not restricted to these three wrappers, you can use
//! any types with proper [`From`] implementation:
//!
//! ```rust
//! use thor_devkit::rlp_encodable;
//!
//! #[derive(Clone)]
//! struct MySeries {
//!     left: [u8; 2],
//!     right: [u8; 2],
//! }
//!
//! impl From<MySeries> for u32 {
//!     fn from(value: MySeries) -> Self {
//!         Self::from_be_bytes(value.left.into_iter().chain(value.right).collect::<Vec<_>>().try_into().unwrap())
//!     }
//! }
//! impl From<u32> for MySeries {
//!     fn from(value: u32) -> Self {
//!         let [a, b, c, d] = value.to_be_bytes();
//!         Self{ left: [a, b], right: [c, d] }
//!     }
//! }
//!
//! rlp_encodable! {
//!     pub struct Foo {
//!         pub foo: MySeries => u32,
//!     }
//! }
//! ```
//!

pub use bytes::{Buf, BufMut, Bytes, BytesMut};
pub use open_fastrlp::{Decodable, DecodeError as RLPError, Encodable, Header};

#[doc(hidden)]
#[macro_export]
macro_rules! __encode_as {
    ($out:expr, $field:expr) => {{
        use $crate::rlp::Encodable;
        $field.encode($out)
    }};
    ($out:expr, $field:expr => $cast:ty) => {{
        use $crate::rlp::Encodable;
        // TODO: this clone bugs me, we should be able to do better
        <$cast>::from($field.clone()).encode($out)
    }};

    ($out:expr, $field:expr $(=> $cast:ty)?, $($fields:expr $(=> $casts:ty)?),+) => {{
        $crate::__encode_as! { $out, $field $(=> $cast)? }
        $crate::__encode_as! { $out, $($fields $(=> $casts)?),+ }
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __decode_as {
    ($buf:expr, $field:ty) => {{
        #[allow(unused_imports)]
        use $crate::rlp::Decodable;
        <$field>::decode($buf)?
    }};
    ($buf:expr, $field:ty => $cast:ty) => {{
        #[allow(unused_imports)]
        use $crate::rlp::Decodable;
        <$field>::from(<$cast>::decode($buf)?)
    }};

    ($buf:expr, $field:ty $(=> $cast:ty)?, $($fields:ty $(=> $casts:ty)?),+) => {{
        $crate::__decode_as! { $buf, $field $(=> $cast)? }
        $crate::__decode_as! { $buf, $($fields $(=> $casts)?),+ }
    }};
}

/// Create an RLP-encodable struct by specifying types to cast to.
#[macro_export]
macro_rules! rlp_encodable {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_attr:meta])*
                $field_vis:vis $field_name:ident: $field_type:ty $(=> $cast:ty)?,
            )*
        }
    ) => {
        $(#[$attr])*
        $vis struct $name {
            $(
                $(#[$field_attr])*
                $field_vis $field_name: $field_type,
            )*
        }

        impl $name {
            fn encode_internal(&self, out: &mut dyn $crate::rlp::BufMut) {
                $crate::__encode_as!(out, $(self.$field_name $(=> $cast)?),+)
            }
        }

        impl $crate::rlp::Encodable for $name {
            fn encode(&self, out: &mut dyn $crate::rlp::BufMut) {
                let mut buf = $crate::rlp::BytesMut::new();
                self.encode_internal(&mut buf);
                $crate::rlp::Header {
                    list: true,
                    payload_length: buf.len()
                }.encode(out);
                out.put_slice(&buf)
            }
        }

        impl $crate::rlp::Decodable for $name {
            fn decode(buf: &mut &[u8]) -> Result<Self, $crate::rlp::RLPError> {
                $crate::rlp::Header::decode(buf)?;
                Ok(Self {
                    $($field_name: $crate::__decode_as!(buf, $field_type $(=> $cast)? )),*
                })
            }
        }
    }
}

/// Serialization wrapper for `Option` to serialize `None` as empty `Bytes`.
///
/// <div class="warning">
///  Do not use it directly: it is only intended for use with `rlp_encodable!` macro.
/// </div>
pub enum AsBytes<T: Encodable + Decodable> {
    #[doc(hidden)]
    Just(T),
    #[doc(hidden)]
    Nothing,
}
impl<T: Encodable + Decodable> Encodable for AsBytes<T> {
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            Self::Just(value) => value.encode(out),
            Self::Nothing => Bytes::new().encode(out),
        }
    }
}
impl<T: Encodable + Decodable, S: Into<T>> From<Option<S>> for AsBytes<T> {
    fn from(value: Option<S>) -> Self {
        match value {
            Some(v) => Self::Just(v.into()),
            None => Self::Nothing,
        }
    }
}
impl<T: Encodable + Decodable> From<AsBytes<T>> for Option<T> {
    fn from(value: AsBytes<T>) -> Self {
        match value {
            AsBytes::Just(v) => Self::Some(v),
            AsBytes::Nothing => Self::None,
        }
    }
}
impl<T: Encodable + Decodable> Decodable for AsBytes<T> {
    fn decode(buf: &mut &[u8]) -> Result<Self, open_fastrlp::DecodeError> {
        if buf[0] == open_fastrlp::EMPTY_STRING_CODE {
            Bytes::decode(buf)?;
            Ok(Self::Nothing)
        } else {
            Ok(Self::Just(T::decode(buf)?))
        }
    }
}

/// Serialization wrapper for `Option` to serialize `None` as empty `Vec`.
///
/// <div class="warning">
///  Do not use it directly: it is only intended for use with `rlp_encodable!` macro.
/// </div>
pub enum AsVec<T: Encodable + Decodable> {
    #[doc(hidden)]
    Just(T),
    #[doc(hidden)]
    Nothing,
}
impl<T: Encodable + Decodable> Encodable for AsVec<T> {
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            Self::Just(value) => value.encode(out),
            Self::Nothing => Vec::<u8>::new().encode(out),
        }
    }
}
impl<T: Encodable + Decodable, S: Into<T>> From<Option<S>> for AsVec<T> {
    fn from(value: Option<S>) -> Self {
        match value {
            Some(v) => Self::Just(v.into()),
            None => Self::Nothing,
        }
    }
}
impl<T: Encodable + Decodable> From<AsVec<T>> for Option<T> {
    fn from(value: AsVec<T>) -> Self {
        match value {
            AsVec::Just(v) => Self::Some(v),
            AsVec::Nothing => Self::None,
        }
    }
}
impl<T: Encodable + Decodable> Decodable for AsVec<T> {
    fn decode(buf: &mut &[u8]) -> Result<Self, open_fastrlp::DecodeError> {
        if buf[0] == open_fastrlp::EMPTY_LIST_CODE {
            Vec::<u8>::decode(buf)?;
            Ok(Self::Nothing)
        } else {
            Ok(Self::Just(T::decode(buf)?))
        }
    }
}

/// Serialization wrapper for `Option` to serialize `None` as nothing (do not modify
/// output stream).
///
/// <div class="warning">
///  Do not use it directly: it is only intended for use with `rlp_encodable!` macro.
/// </div>
pub enum Maybe<T: Encodable + Decodable> {
    #[doc(hidden)]
    Just(T),
    #[doc(hidden)]
    Nothing,
}
impl<T: Encodable + Decodable> Encodable for Maybe<T> {
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            Self::Just(value) => value.encode(out),
            Self::Nothing => (),
        }
    }
}
impl<T: Encodable + Decodable> Decodable for Maybe<T> {
    fn decode(buf: &mut &[u8]) -> Result<Self, open_fastrlp::DecodeError> {
        if buf.remaining() == 0 {
            Ok(Self::Nothing)
        } else {
            Ok(Self::Just(T::decode(buf)?))
        }
    }
}
impl<T: Encodable + Decodable, S: Into<T>> From<Option<S>> for Maybe<T> {
    fn from(value: Option<S>) -> Self {
        match value {
            Some(v) => Self::Just(v.into()),
            None => Self::Nothing,
        }
    }
}
impl<T: Encodable + Decodable> From<Maybe<T>> for Option<T> {
    fn from(value: Maybe<T>) -> Self {
        match value {
            Maybe::Just(v) => Self::Some(v),
            Maybe::Nothing => Self::None,
        }
    }
}

#[inline]
pub(crate) fn lstrip<S: AsRef<[u8]>>(bytes: S) -> Vec<u8> {
    bytes
        .as_ref()
        .iter()
        .skip_while(|&&x| x == 0)
        .copied()
        .collect()
}

#[inline]
pub(crate) fn static_left_pad<const N: usize>(
    data: &[u8],
) -> Result<[u8; N], open_fastrlp::DecodeError> {
    if data.len() > N {
        return Err(open_fastrlp::DecodeError::Overflow);
    }

    let mut v = [0; N];

    if data.is_empty() {
        return Ok(v);
    }

    if data[0] == 0 {
        return Err(open_fastrlp::DecodeError::LeadingZero);
    }

    // SAFETY: length checked above
    unsafe { v.get_unchecked_mut(N - data.len()..) }.copy_from_slice(data);
    Ok(v)
}
