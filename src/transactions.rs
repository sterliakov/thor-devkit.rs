//! VeChain transactions support.

use crate::address::{Address, AddressConvertible, PrivateKey};
use crate::utils::blake2_256;
pub use alloy_rlp::Bytes;
use alloy_rlp::{BufMut, Encodable, RlpEncodable};
pub use ethnum::U256;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1};

fn lstrip<S: AsRef<[u8]>>(bytes: S) -> Vec<u8> {
    bytes
        .as_ref()
        .iter()
        .skip_while(|&&x| x == 0)
        .copied()
        .collect()
}

/// Represents a single VeChain transaction.
#[derive(Clone)]
pub struct Transaction {
    /// Chain tag
    pub chain_tag: u8,
    /// Previous block reference
    ///
    /// First 4 bytes are block height, the rest is part of referred block ID.
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
    pub depends_on: Option<[u8; 64]>,
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

#[derive(Clone, RlpEncodable)]
struct WrappedTransaction {
    body: InternalTransactionBody,
}

#[derive(Clone)]
struct InternalTransactionBody(Transaction);

// TODO: add decoding capabilities
// TODO: add serde optional support
impl Encodable for InternalTransactionBody {
    fn encode(&self, out: &mut dyn BufMut) {
        self.0.chain_tag.encode(out);
        self.0.block_ref.encode(out);
        self.0.expiration.encode(out);
        self.0.clauses.encode(out);
        self.0.gas_price_coef.encode(out);
        self.0.gas.encode(out);
        if let Some(a) = self.0.depends_on.as_ref() {
            Bytes::copy_from_slice(a).encode(out)
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
impl Encodable for Transaction {
    fn encode(&self, out: &mut dyn BufMut) {
        WrappedTransaction {
            body: InternalTransactionBody(self.clone()),
        }
        .encode(out)
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
        blake2_256(&[&main_hash[..], &delegate_for.to_bytes()[..]])
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

    pub fn with_signature(self, signature: Bytes) -> Result<Self, secp256k1::Error> {
        //! Set a signature for this transaction.
        if self.is_delegated() && signature.len() == 130
            || !self.is_delegated() && signature.len() == 65
        {
            Ok(Self {
                signature: Some(signature),
                ..self
            })
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
            Some(signature) => {
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
            Some(signature) => {
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
                &origin.address().to_bytes()[..],
            ]))),
        }
    }
}

/// Represents a single transaction clause (recipient, value and data).
#[derive(Clone)]
pub struct Clause {
    /// Recipient
    pub to: Option<Address>,
    /// Amount of funds to spend.
    pub value: U256,
    /// Contract code or other data.
    pub data: Bytes,
}

impl Encodable for Clause {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut enc = vec![];
        self.encode_internal(&mut enc);
        alloy_rlp::Header {
            list: true,
            payload_length: enc.len(),
        }
        .encode(out);
        out.put_slice(&enc);
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

    fn encode_internal(&self, out: &mut dyn BufMut) {
        if let Some(a) = self.to {
            a.encode(out)
        } else {
            b"".to_vec().encode(out);
        }

        let value = lstrip(self.value.to_be_bytes());
        Bytes::from(value).encode(out);

        self.data.encode(out);
    }

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
#[derive(Clone)]
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
    pub fn is_delegated(&self) -> bool {
        //! Belongs to delegated transaction?
        self.features & Self::DELEGATED_BIT != 0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::address::decode_hex;

    const PK_STRING: &str = "7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a";
    macro_rules! make_pk {
        () => {
            PrivateKey::from_slice(&decode_hex(PK_STRING).unwrap()).unwrap()
        };
        ($hex:expr) => {
            PrivateKey::from_slice(&decode_hex($hex).unwrap()).unwrap()
        };
    }

    macro_rules! undelegated_tx {
        () => {
            Transaction {
                chain_tag: 1,
                block_ref: 0xaabbccdd,
                expiration: 32,
                clauses: vec![
                    Clause {
                        to: Some(
                            "0x7567d83b7b8d80addcb281a71d54fc7b3364ffed"
                                .parse()
                                .unwrap(),
                        ),
                        value: U256::new(10000),
                        data: b"\x00\x00\x00\x60\x60\x60".to_vec().into(),
                    },
                    Clause {
                        to: Some(
                            "0x7567d83b7b8d80addcb281a71d54fc7b3364ffed"
                                .parse()
                                .unwrap(),
                        ),
                        value: U256::new(20000),
                        data: b"\x00\x00\x00\x60\x60\x60".to_vec().into(),
                    },
                ],
                gas_price_coef: 128,
                gas: 21000,
                depends_on: None,
                nonce: 0xbc614e,
                reserved: None,
                signature: None,
            }
        };
    }

    macro_rules! delegated_tx {
        () => {
            Transaction {
                reserved: Some(Reserved {
                    features: 1,
                    unused: vec![Bytes::from(b"1234".to_vec())],
                }),
                ..undelegated_tx!()
            }
        };
    }

    #[test]
    fn test_rlp_encode_basic() {
        let tx = undelegated_tx!();
        let expected = decode_hex(
            "f8540184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0"
        ).unwrap();
        let mut buf = vec![];
        tx.encode(&mut buf);
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_rlp_encode_delegated() {
        let tx = delegated_tx!();
        let expected = decode_hex(
            "f85a0184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec6018431323334"
        ).unwrap();
        let mut buf = vec![];
        tx.encode(&mut buf);
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_rlp_encode_reserved_unused_untrimmed() {
        let tx = Transaction {
            reserved: Some(Reserved {
                features: 0,
                unused: vec![Bytes::new()],
            }),
            ..undelegated_tx!()
        };
        let expected = decode_hex(
            "f8540184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0"
        ).unwrap();
        let mut buf = vec![];
        tx.encode(&mut buf);
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_rlp_encode_reserved_features() {
        let tx = Transaction {
            reserved: Some(Reserved {
                features: 0,
                unused: vec![],
            }),
            ..undelegated_tx!()
        };
        let tx2 = Transaction {
            reserved: None,
            ..undelegated_tx!()
        };
        let mut buf = vec![];
        tx.encode(&mut buf);
        let mut buf2 = vec![];
        tx2.encode(&mut buf2);
        assert_eq!(buf, buf2);
    }

    #[test]
    fn test_rlp_encode_reserved_unused() {
        let reserved = Reserved {
            features: 1,
            unused: vec![
                Bytes::from(b"\x0F\x0F".to_vec()),
                Bytes::from(b"\x01\x01".to_vec()),
            ],
        };
        let mut buf = vec![];
        reserved.encode(&mut buf);
        assert_eq!(buf, vec![0xC7, 0x01, 0x82, 0x0F, 0x0F, 0x82, 0x01, 0x01],)
    }

    #[test]
    fn test_rlp_encode_reserved_unused_2() {
        let reserved = Reserved {
            features: 1,
            unused: vec![Bytes::from(b"\x0F\x0F".to_vec()), Bytes::new()],
        };
        let mut buf = vec![];
        reserved.encode(&mut buf);
        assert_eq!(buf, vec![0xC4, 0x01, 0x82, 0x0F, 0x0F],)
    }

    #[test]
    fn test_rlp_encode_reserved_unused_3() {
        let reserved = Reserved {
            features: 0,
            unused: vec![Bytes::from(b"\x0F\x0F".to_vec()), Bytes::new()],
        };
        let mut buf = vec![];
        reserved.encode(&mut buf);
        assert_eq!(buf, vec![0xC4, 0x80, 0x82, 0x0F, 0x0F],)
    }

    #[test]
    fn test_sign_undelegated() {
        let tx = undelegated_tx!();
        let expected = decode_hex(
            "f8540184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0"
        ).unwrap();
        let mut buf = vec![];
        tx.encode(&mut buf);
        assert_eq!(buf, expected);

        let pk = make_pk!();
        let hash = tx.get_signing_hash();
        assert_eq!(
            hash.to_vec(),
            decode_hex("2a1c25ce0d66f45276a5f308b99bf410e2fc7d5b6ea37a49f2ab9f1da9446478").unwrap()
        );
        let signature = Transaction::sign_hash(hash, &pk);
        assert_eq!(
            signature.to_vec(),
            decode_hex("f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00").unwrap()
        );

        let signed = tx.sign(&pk);
        assert_eq!(signed.signature.unwrap(), signature.to_vec())
    }

    #[test]
    fn test_sign_delegated() {
        let tx = delegated_tx!();
        let sender = make_pk!("58e444d4fe08b0f4d9d86ec42f26cf15072af3ddc29a78e33b0ceaaa292bcf6b");
        let gas_payer =
            make_pk!("0bfd6a863f347f4ef2cf2d09c3db7b343d84bb3e6fc8c201afee62de6381dc65");

        let sender_sig = Transaction::sign_hash(tx.get_signing_hash(), &sender);
        let gas_payer_sig = Transaction::sign_hash(
            tx.get_delegate_signing_hash(&sender.public_key(&Secp256k1::signing_only()).address()),
            &gas_payer,
        );
        let tx = tx
            .with_signature(sender_sig.into_iter().chain(gas_payer_sig).collect())
            .unwrap();
        assert_eq!(
            tx.origin().unwrap(),
            Some(sender.public_key(&Secp256k1::signing_only()))
        );
        assert_eq!(
            tx.delegator().unwrap(),
            Some(gas_payer.public_key(&Secp256k1::signing_only()))
        );
    }

    #[test]
    fn test_undelegated_signed_properties() {
        let pk = make_pk!();
        let tx = undelegated_tx!().sign(&pk);
        assert_eq!(
            tx.signature.clone().unwrap(),
            decode_hex("f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00").unwrap(),
        );
        let pubkey = pk.public_key(&Secp256k1::signing_only());
        assert_eq!(tx.origin().unwrap().unwrap(), pubkey);
        assert_eq!(
            tx.id().unwrap().unwrap().to_vec(),
            decode_hex("da90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec").unwrap()
        );
        assert_eq!(
            &tx.get_delegate_signing_hash(&pubkey.address())[..],
            decode_hex("da90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec").unwrap()
        );
    }

    #[test]
    fn test_undelegated_unsigned_properties() {
        let tx = undelegated_tx!();
        assert!(!tx.is_delegated());
        assert_eq!(tx.signature, None);
        assert_eq!(tx.id(), Ok(None));
        assert_eq!(tx.origin(), Ok(None));
        assert_eq!(tx.delegator(), Ok(None));
    }

    #[test]
    fn test_intrinsic_gas() {
        let tx = undelegated_tx!();
        assert_eq!(tx.intrinsic_gas(), 37_432);
    }

    #[test]
    fn test_intrinsic_gas_empty() {
        let tx = Transaction {
            clauses: vec![],
            ..undelegated_tx!()
        };
        assert_eq!(tx.intrinsic_gas(), 21_000);
    }

    #[test]
    fn test_intrinsic_gas_2() {
        let tx = Transaction {
            clauses: vec![Clause {
                to: None,
                value: U256::new(0),
                data: Bytes::new(),
            }],
            ..undelegated_tx!()
        };
        assert_eq!(tx.intrinsic_gas(), 53_000);
        let mut buf = vec![];
        tx.encode(&mut buf); // Must not fail
    }
}
