//! VeChain transactions support.

use crate::address::{Address, AddressConvertible, PrivateKey};
use crate::utils::blake2_256;
use alloy_rlp::{Buf, BufMut, RlpDecodable, RlpEncodable};
pub use alloy_rlp::{Bytes, Decodable, Encodable};
use ethereum_types::U256;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1};

pub(crate) fn lstrip<S: AsRef<[u8]>>(bytes: S) -> Vec<u8> {
    bytes
        .as_ref()
        .iter()
        .skip_while(|&&x| x == 0)
        .copied()
        .collect()
}

/// Represents a single VeChain transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    /// Chain tag
    pub chain_tag: u8,
    /// Previous block reference
    ///
    /// First 4 bytes (BE) are block height, the rest is part of referred block ID.
    pub block_ref: u64,
    /// Expiration (in blocks)
    pub expiration: u32,
    /// Vector of clauses
    pub clauses: Vec<Clause>,
    /// Coefficient to calculate the gas price.
    pub gas_price_coef: u8,
    /// Maximal amount of gas to spend for transaction.
    pub gas: u64,
    /// Hash of transaction on which current transaction depends.
    ///
    /// May be left unspecified if this functionality is not necessary.
    pub depends_on: Option<U256>,
    /// Transaction nonce
    pub nonce: u64,
    /// Reserved fields.
    pub reserved: Option<Reserved>,
    /// Signature. 65 bytes for regular transactions, 130 - for VIP-191.
    ///
    /// Ignored when making a signing hash.
    ///
    /// For VIP-191 transactions, this would be a simple concatenation
    /// of two signatures.
    pub signature: Option<Bytes>,
}

#[derive(Clone, Debug, Eq, PartialEq, RlpEncodable, RlpDecodable)]
struct WrappedInternalTransaction {
    body: InternalTransaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InternalTransaction(Transaction);

// TODO: add serde optional support
impl Encodable for InternalTransaction {
    fn encode(&self, out: &mut dyn BufMut) {
        self.0.chain_tag.encode(out);
        self.0.block_ref.encode(out);
        self.0.expiration.encode(out);
        self.0.clauses.encode(out);
        self.0.gas_price_coef.encode(out);
        self.0.gas.encode(out);
        if let Some(a) = self.0.depends_on.as_ref() {
            let mut buf = [0; 32];
            a.to_big_endian(&mut buf);
            Bytes::copy_from_slice(&buf).encode(out)
        } else {
            Bytes::new().encode(out);
        }
        self.0.nonce.encode(out);
        if let Some(r) = self.0.reserved.as_ref() {
            r.encode(out)
        } else {
            b"".to_vec().encode(out);
        }
        if let Some(s) = self.0.signature.as_ref() {
            s.encode(out);
        }
    }
}
impl Decodable for InternalTransaction {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        alloy_rlp::Header::decode(buf)?;
        let tx = Self(Transaction {
            chain_tag: u8::decode(buf)?,
            block_ref: u64::decode(buf)?,
            expiration: u32::decode(buf)?,
            clauses: Vec::<Clause>::decode(buf)?,
            gas_price_coef: u8::decode(buf)?,
            gas: u64::decode(buf)?,
            depends_on: {
                let binary = Bytes::decode(buf)?;
                if binary.is_empty() {
                    None
                } else {
                    Some(U256::from_big_endian(
                        &static_left_pad::<32>(&binary).map_err(|_| {
                            alloy_rlp::Error::ListLengthMismatch {
                                expected: 32,
                                got: binary.len(),
                            }
                        })?,
                    ))
                }
            },
            nonce: u64::decode(buf)?,
            reserved: {
                let reserved = Reserved::decode(buf)?;
                if reserved.is_empty() {
                    None
                } else {
                    Some(reserved)
                }
            },
            signature: {
                if buf.remaining() == 0 {
                    None
                } else {
                    Some(Bytes::decode(buf)?)
                }
            },
        });
        if tx.0.signature_length_valid() {
            Ok(tx)
        } else {
            Err(alloy_rlp::Error::ListLengthMismatch {
                expected: if tx.0.is_delegated() { 130 } else { 65 },
                got: tx.0.signature.expect("Already checked to be present").len(),
            })
        }
    }
}

impl Encodable for Transaction {
    fn encode(&self, out: &mut dyn BufMut) {
        WrappedInternalTransaction {
            body: InternalTransaction(self.clone()),
        }
        .encode(out)
    }
}
impl Decodable for Transaction {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        let WrappedInternalTransaction {
            body: InternalTransaction(clause),
        } = WrappedInternalTransaction::decode(buf)?;
        Ok(clause)
    }
}

impl Transaction {
    /// Gas cost for whole transaction execution.
    pub const TRANSACTION_GAS: u64 = 5_000;

    pub fn get_signing_hash(&self) -> [u8; 32] {
        //! Get a signing hash for this transaction.
        let mut encoded = Vec::with_capacity(1024);
        let mut without_signature = self.clone();
        without_signature.signature = None;
        without_signature.encode(&mut encoded);
        blake2_256(&[encoded])
    }

    pub fn get_delegate_signing_hash(&self, delegate_for: &Address) -> [u8; 32] {
        //! Get a signing hash for this transaction with fee delegation.
        //!
        //! `VIP-191 <https://github.com/vechain/VIPs/blob/master/vips/VIP-191.md>`
        let mut encoded = Vec::with_capacity(1024);
        let mut without_signature = self.clone();
        without_signature.signature = None;
        without_signature.encode(&mut encoded);
        let main_hash = blake2_256(&[encoded]);
        blake2_256(&[&main_hash[..], &delegate_for.to_fixed_bytes()[..]])
    }

    pub fn sign(self, private_key: &PrivateKey) -> Self {
        //! Create a copy of transaction with a signature emplaced.
        //!
        //! You can call `.encode()` on the result to get bytes ready to be sent
        //! over wire.
        let hash = self.get_signing_hash();
        let signature = Self::sign_hash(hash, private_key);
        self.with_signature(Bytes::copy_from_slice(&signature))
            .expect("generated signature must be correct")
    }

    fn signature_length_valid(&self) -> bool {
        match &self.signature {
            None => true,
            Some(signature) => {
                self.is_delegated() && signature.len() == 130
                    || !self.is_delegated() && signature.len() == 65
            }
        }
    }

    pub fn with_signature(self, signature: Bytes) -> Result<Self, secp256k1::Error> {
        //! Set a signature for this transaction.
        let copy = Self {
            signature: Some(signature),
            ..self
        };
        if copy.signature_length_valid() {
            Ok(copy)
        } else {
            Err(secp256k1::Error::IncorrectSignature)
        }
    }

    pub fn sign_hash(hash: [u8; 32], private_key: &PrivateKey) -> [u8; 65] {
        //! Sign a hash obtained from `Transaction::get_signing_hash`.
        let secp = Secp256k1::signing_only();
        let signature =
            secp.sign_ecdsa_recoverable(&Message::from_slice(&hash).unwrap(), private_key);
        let (recovery_id, bytes) = signature.serialize_compact();
        bytes
            .into_iter()
            .chain([recovery_id.to_i32() as u8])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    pub fn intrinsic_gas(&self) -> u64 {
        //! Calculate the intrinsic gas amount required for this transaction.
        //!
        //! This amount is always less than actual amount of gas necessary.
        //! `More info <https://docs.vechain.org/core-concepts/transactions/transaction-calculation>`
        let clauses_cost = if self.clauses.is_empty() {
            Clause::REGULAR_CLAUSE_GAS
        } else {
            self.clauses.iter().map(Clause::intrinsic_gas).sum()
        };
        clauses_cost + Self::TRANSACTION_GAS
    }

    pub fn origin(&self) -> Result<Option<PublicKey>, secp256k1::Error> {
        //! Recover origin public key using the signature.
        //!
        //! Returns `Ok(None)` if signature is unset.
        match &self.signature {
            None => Ok(None),
            Some(signature) if self.signature_length_valid() => {
                let hash = self.get_signing_hash();
                let secp = Secp256k1::verification_only();

                Ok(Some(secp.recover_ecdsa(
                    &Message::from_slice(&hash)?,
                    &RecoverableSignature::from_compact(
                        &signature[..64],
                        RecoveryId::from_i32(signature[64] as i32)?,
                    )?,
                )?))
            }
            _ => Err(secp256k1::Error::IncorrectSignature),
        }
    }

    pub fn delegator(&self) -> Result<Option<PublicKey>, secp256k1::Error> {
        //! Recover delegator public key using the signature.
        //!
        //! Returns `Ok(None)` if signature is unset or transaction is not delegated.
        if !self.is_delegated() {
            return Ok(None);
        }
        match &self.signature {
            None => Ok(None),
            Some(signature) if self.signature_length_valid() => {
                let hash = self.get_delegate_signing_hash(
                    &self
                        .origin()?
                        .expect("Must be set, already checked signature")
                        .address(),
                );
                let secp = Secp256k1::verification_only();

                Ok(Some(secp.recover_ecdsa(
                    &Message::from_slice(&hash)?,
                    &RecoverableSignature::from_compact(
                        &signature[65..129],
                        RecoveryId::from_i32(signature[129] as i32)?,
                    )?,
                )?))
            }
            _ => Err(secp256k1::Error::IncorrectSignature),
        }
    }

    pub fn is_delegated(&self) -> bool {
        //! Check if transaction is VIP-191 delegated.
        if let Some(reserved) = &self.reserved {
            reserved.is_delegated()
        } else {
            false
        }
    }

    pub fn id(&self) -> Result<Option<[u8; 32]>, secp256k1::Error> {
        //! Calculate transaction ID using the signature.
        //!
        //! Returns `Ok(None)` if signature is unset.
        match self.origin()? {
            None => Ok(None),
            Some(origin) => Ok(Some(blake2_256(&[
                &self.get_signing_hash()[..],
                &origin.address().to_fixed_bytes()[..],
            ]))),
        }
    }

    pub fn has_valid_signature(&self) -> bool {
        //! Check wheter the signature is valid.
        self._has_valid_signature().unwrap_or(false)
    }

    fn _has_valid_signature(&self) -> Result<bool, secp256k1::Error> {
        //! Check wheter the signature is valid.
        if !self.signature_length_valid() {
            return Ok(false);
        }
        match &self.signature {
            None => Ok(false),
            Some(signature) => {
                let hash = self.get_signing_hash();
                let secp = Secp256k1::verification_only();
                Ok(secp
                    .recover_ecdsa(
                        &Message::from_slice(&hash)?,
                        &RecoverableSignature::from_compact(
                            &signature[..64],
                            RecoveryId::from_i32(signature[64] as i32)?,
                        )?,
                    )
                    .is_ok())
            }
        }
    }

    pub fn to_broadcastable_bytes(&self) -> Result<Bytes, secp256k1::Error> {
        //! Create a binary representation.
        //!
        //! Returns `Err(secp256k1::Error::IncorrectSignature)` if signature is not set.
        if self.signature.is_some() {
            let mut buf = alloy_rlp::BytesMut::new();
            self.encode(&mut buf);
            Ok(buf.into())
        } else {
            Err(secp256k1::Error::IncorrectSignature)
        }
    }
}

/// Represents a single transaction clause (recipient, value and data).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Clause {
    /// Recipient
    pub to: Option<Address>,
    /// Amount of funds to spend.
    pub value: U256,
    /// Contract code or other data.
    pub data: Bytes,
}

#[derive(Clone)]
struct InternalClause(Clause);
#[derive(Clone, RlpEncodable, RlpDecodable)]
struct WrappedInternalClause(InternalClause);

impl Encodable for Clause {
    fn encode(&self, out: &mut dyn BufMut) {
        WrappedInternalClause(InternalClause(self.clone())).encode(out)
    }
}
impl Decodable for Clause {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        let WrappedInternalClause(InternalClause(clause)) = WrappedInternalClause::decode(buf)?;
        Ok(clause)
    }
}

impl Encodable for InternalClause {
    fn encode(&self, out: &mut dyn BufMut) {
        if let Some(a) = self.0.to {
            a.encode(out)
        } else {
            Bytes::new().encode(out);
        }

        let value = {
            let mut buf = [0; 32];
            self.0.value.to_big_endian(&mut buf);
            lstrip(buf)
        };
        Bytes::from(value).encode(out);

        self.0.data.encode(out);
    }
}
impl Decodable for InternalClause {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        Ok(Self(Clause {
            to: {
                let address = Address::decode(buf)?;
                if address.to_fixed_bytes() == [0; 20] {
                    // None is zero address (contract creation). It is not
                    // distinguishable from real [0; 20] address by design:
                    // null address is a really existing one, parent of contracts.
                    None
                } else {
                    Some(address)
                }
            },
            value: U256::from_big_endian(&static_left_pad::<32>(&Bytes::decode(buf)?)?),
            data: Bytes::decode(buf)?,
        }))
    }
}

impl Clause {
    /// Gas spent for one regular clause execution.
    pub const REGULAR_CLAUSE_GAS: u64 = 16_000;
    /// Gas spent for one contract creation (without `to`) clause execution.
    pub const CONTRACT_CREATION_CLAUSE_GAS: u64 = 48_000;
    /// Intrinsic gas usage for a single zero byte of data.
    pub const ZERO_DATA_BYTE_GAS_COST: u64 = 4;
    /// Intrinsic gas usage for a single non-zero byte of data.
    pub const NONZERO_DATA_BYTE_GAS_COST: u64 = 68;

    pub fn intrinsic_gas(&self) -> u64 {
        //! Calculate the intrinsic gas amount required for executing this clause.
        //!
        //! This amount is always less than actual amount of gas necessary.
        //! `More info <https://docs.vechain.org/core-concepts/transactions/transaction-calculation>`
        let clause_gas = if self.to.is_some() {
            Self::REGULAR_CLAUSE_GAS
        } else {
            Self::CONTRACT_CREATION_CLAUSE_GAS
        };
        let data_gas: u64 = self
            .data
            .iter()
            .map(|&b| {
                if b == 0 {
                    Self::ZERO_DATA_BYTE_GAS_COST
                } else {
                    Self::NONZERO_DATA_BYTE_GAS_COST
                }
            })
            .sum();
        clause_gas + data_gas
    }
}

/// Represents a transaction's ``reserved`` field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reserved {
    /// Features to enable (bitmask).
    pub features: u32,
    /// Currently unused field.
    pub unused: Vec<Bytes>,
}

impl Encodable for Reserved {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut buf = vec![];
        self.features.to_be_bytes().encode(&mut buf);
        let mut stripped_buf: Vec<_> = [lstrip(&buf[1..])]
            .into_iter()
            .map(Bytes::from)
            .chain(self.unused.clone())
            .rev()
            .skip_while(Bytes::is_empty)
            .collect();
        stripped_buf.reverse();
        stripped_buf.encode(out)
    }
}

impl Decodable for Reserved {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        if let Some((feature_bytes, unused)) = Vec::<Bytes>::decode(buf)?.split_first() {
            Ok(Self {
                features: u32::from_be_bytes(static_left_pad(feature_bytes)?),
                unused: unused.to_vec(),
            })
        } else {
            Ok(Self::new_empty())
        }
    }
}

impl Reserved {
    /// Features bitmask for delegated transaction.
    pub const DELEGATED_BIT: u32 = 1;

    pub fn new_delegated() -> Self {
        //! Create reserved structure kind for VIP-191 delegation.
        Self {
            features: Self::DELEGATED_BIT,
            unused: vec![],
        }
    }
    pub fn new_empty() -> Self {
        //! Create reserved structure kind for regular transaction.
        Self {
            features: 0,
            unused: vec![],
        }
    }
    pub fn is_delegated(&self) -> bool {
        //! Belongs to delegated transaction?
        self.features & Self::DELEGATED_BIT != 0
    }
    pub fn is_empty(&self) -> bool {
        //! Belongs to delegated transaction?
        self.features == 0 && self.unused.is_empty()
    }
}

#[inline]
pub(crate) fn static_left_pad<const N: usize>(data: &[u8]) -> Result<[u8; N], alloy_rlp::Error> {
    if data.len() > N {
        return Err(alloy_rlp::Error::Overflow);
    }

    let mut v = [0; N];

    if data.is_empty() {
        return Ok(v);
    }

    if data[0] == 0 {
        return Err(alloy_rlp::Error::LeadingZero);
    }

    // SAFETY: length checked above
    unsafe { v.get_unchecked_mut(N - data.len()..) }.copy_from_slice(data);
    Ok(v)
}
