//! VeChain transactions support.

use crate::address::{Address, PrivateKey};
use crate::utils::blake2_256;
pub use alloy_rlp::Bytes;
use alloy_rlp::{BufMut, Encodable, RlpEncodable};
pub use ethnum::U256;
use secp256k1::{Message, Secp256k1};

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
            Bytes::from(a.to_vec()).encode(out)
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
    pub fn get_signing_hash(&self) -> [u8; 32] {
        //! Get a signing hash for this transaction.
        let mut encoded = Vec::with_capacity(1024);
        let mut without_signature = self.clone();
        without_signature.signature = None;
        without_signature.encode(&mut encoded);
        blake2_256(&[encoded])
    }

    pub fn get_delegated_signing_hash(&self, delegate_for: &Address) -> [u8; 32] {
        //! Get a signing hash for this transaction with fee delegation (VIP-191).
        let mut encoded = Vec::with_capacity(1024);
        let mut without_signature = self.clone();
        without_signature.signature = None;
        without_signature.encode(&mut encoded);
        let main_hash = blake2_256(&[encoded]);
        blake2_256(&[main_hash.to_vec(), delegate_for.to_bytes().to_vec()])
    }

    pub fn sign(self, private_key: PrivateKey) -> Self {
        //! Create a copy of transaction with a signature emplaced.
        //!
        //! You can call `.encode()` on the result to get bytes ready to be sent
        //! over wire.
        let hash = self.get_signing_hash();
        let signature = Self::sign_hash(hash, private_key);
        Self {
            signature: Some(Bytes::copy_from_slice(&signature)),
            ..self
        }
    }

    pub fn sign_hash(hash: [u8; 32], private_key: PrivateKey) -> [u8; 65] {
        //! Sign a hash obtained from `Transaction::get_signing_hash`.
        let secp = Secp256k1::signing_only();
        let signature =
            secp.sign_ecdsa_recoverable(&Message::from_slice(&hash).unwrap(), &private_key);
        let (recovery_id, bytes) = signature.serialize_compact();
        bytes
            .into_iter()
            .chain([recovery_id.to_i32() as u8])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
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
}

/// Represents a transaction's ``reserved`` field.
#[derive(Clone)]
pub struct Reserved {
    /// Features to enable.
    pub features: u32,
    /// Currently unused field.
    pub unused: Vec<Bytes>,
}

impl Encodable for Reserved {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut buf = vec![];
        self.features.encode(&mut buf);
        let mut stripped_buf: Vec<_> = [buf]
            .into_iter()
            .map(Bytes::from)
            .chain(self.unused.clone())
            .rev()
            .skip_while(|b| b.is_empty())
            .collect();
        stripped_buf.reverse();
        stripped_buf.encode(out)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::address::decode_hex;

    #[test]
    fn test_rlp_encode_basic() {
        let tx = Transaction {
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
        };
        let expected = decode_hex(
            "f8540184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec0"
        ).unwrap();
        let mut buf = vec![];
        tx.encode(&mut buf);
        assert_eq!(buf, expected);

        let pk_str = "7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a";
        let pk = PrivateKey::from_slice(&decode_hex(pk_str).unwrap()).unwrap();
        let signature = Transaction::sign_hash(tx.get_signing_hash(), pk);
        assert_eq!(
            signature.to_vec(),
            decode_hex("f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00").unwrap()
        );
    }

    #[test]
    fn test_rlp_encode_delegated() {
        let tx = Transaction {
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
            reserved: Some(Reserved {
                features: 1,
                unused: vec![Bytes::from(b"1234".to_vec())],
            }),
            signature: None,
        };
        let expected = decode_hex(
            "f85a0184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec6018431323334"
        ).unwrap();
        let mut buf = vec![];
        tx.encode(&mut buf);
        assert_eq!(buf, expected);
    }
}
