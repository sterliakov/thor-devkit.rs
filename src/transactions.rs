//! VeChain transactions support.
use crate::address::Address;
use alloy_rlp::{BufMut, Bytes, Encodable, RlpEncodable};
use ethnum::U256;

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
    /// Signature. Set to None before signing.
    pub signature: Option<[u8; 65]>,
}

#[derive(Clone, RlpEncodable)]
struct WrappedTransaction {
    body: InternalTransactionBody,
}

#[derive(Clone)]
struct InternalTransactionBody(Transaction);

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
            Bytes::from(s.to_vec()).encode(out);
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
    pub unused: Bytes,
}

impl Encodable for Reserved {
    fn encode(&self, out: &mut dyn BufMut) {
        let mut buf = vec![];
        self.features.encode(&mut buf);
        self.unused.encode(&mut buf);
        let mut stripped_buf = lstrip(buf);
        stripped_buf.reverse();
        out.put_slice(&stripped_buf)
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
    }
}
