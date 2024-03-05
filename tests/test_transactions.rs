use rustc_hex::FromHex;
use secp256k1::Secp256k1;
use thor_devkit::rlp::{Bytes, Decodable, Encodable, RLPError};
use thor_devkit::transactions::*;
use thor_devkit::U256;
use thor_devkit::{AddressConvertible, PrivateKey};

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.from_hex().unwrap()
}

const PK_STRING: &str = "7582be841ca040aa940fff6c05773129e135623e41acce3e0b8ba520dc1ae26a";
macro_rules! make_pk {
    () => {
        PrivateKey::from_slice(&decode_hex(PK_STRING)).unwrap()
    };
    ($hex:expr) => {
        PrivateKey::from_slice(&decode_hex($hex)).unwrap()
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
                    value: 10000.into(),
                    data: b"\x00\x00\x00\x60\x60\x60".to_vec().into(),
                },
                Clause {
                    to: Some(
                        "0x7567d83b7b8d80addcb281a71d54fc7b3364ffed"
                            .parse()
                            .unwrap(),
                    ),
                    value: 20000.into(),
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
    );
    let mut buf = vec![];
    tx.encode(&mut buf);
    assert_eq!(buf, expected);
    assert_eq!(
        Transaction::decode(&mut &buf[..]).expect("Must be decodable"),
        tx
    );
    assert!(!tx.has_valid_signature());
    assert_eq!(
        tx.to_broadcastable_bytes().expect_err("Unsigned"),
        secp256k1::Error::IncorrectSignature
    );
}

#[test]
fn test_rlp_encode_basic_contract() {
    let tx = Transaction {
        clauses: vec![Clause {
            to: None,
            value: 0.into(),
            data: b"\x12\x34".to_vec().into(),
        }],
        ..undelegated_tx!()
    };
    let expected = decode_hex("d90184aabbccdd20c6c5808082123481808252088083bc614ec0");
    let mut buf = vec![];
    tx.encode(&mut buf);
    buf.iter().for_each(|c| print!("{:02x?}", c));
    assert_eq!(buf, expected);
    assert_eq!(
        Transaction::decode(&mut &buf[..]).expect("Must be decodable"),
        tx
    );
}

#[test]
fn test_rlp_encode_delegated() {
    let tx = delegated_tx!();
    let expected = decode_hex(
        "f85a0184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e208600000060606081808252088083bc614ec6018431323334"
    );
    let mut buf = vec![];
    tx.encode(&mut buf);
    assert_eq!(buf, expected);
    assert_eq!(
        Transaction::decode(&mut &buf[..]).expect("Must be decodable"),
        tx
    );
    assert!(!tx.has_valid_signature());
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
    );
    let mut buf = vec![];
    tx.encode(&mut buf);
    assert_eq!(buf, expected);
    // Whole reserved component should've been trimmed
    assert_eq!(
        Transaction::decode(&mut &buf[..]).expect("Must be decodable"),
        undelegated_tx!()
    );
}

#[test]
fn test_rlp_encode_reserved_can_be_omitted() {
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
    let tx_delegated = Transaction {
        reserved: Some(Reserved::new_delegated()),
        ..undelegated_tx!()
    };
    let mut buf = vec![];
    tx.encode(&mut buf);
    let mut buf2 = vec![];
    tx2.encode(&mut buf2);
    assert_eq!(buf, buf2);
    let mut buf3 = vec![];
    tx_delegated.encode(&mut buf3);
    assert_ne!(buf, buf3);
}

#[test]
fn test_rlp_encode_depends_on() {
    // Verified on-chain after signing.
    let tx = Transaction {
        depends_on: Some(U256::from_big_endian(&decode_hex(
            "360341090d2c4a01fa7da816c57d51c0b2fa3fcf1f99141806efc99f568c0b2a",
        ))),
        ..undelegated_tx!()
    };
    let mut buf = vec![];
    tx.encode(&mut buf);
    let expected = decode_hex("f8740184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e20860000006060608180825208a0360341090d2c4a01fa7da816c57d51c0b2fa3fcf1f99141806efc99f568c0b2a83bc614ec0");
    assert_eq!(buf, expected);

    assert_eq!(
        Transaction::decode(&mut &buf[..]).expect("Must be decodable"),
        tx
    );
}

#[test]
fn test_rlp_encode_depends_on_malformed() {
    // Manually crafted: here depends_on is 33 bytes long.
    let malformed = decode_hex("f8750184aabbccdd20f840df947567d83b7b8d80addcb281a71d54fc7b3364ffed82271086000000606060df947567d83b7b8d80addcb281a71d54fc7b3364ffed824e20860000006060608180825208a136034141090d2c4a01fa7da816c57d51c0b2fa3fcf1f99141806efc99f568c0b2a83bc614ec0");
    assert_eq!(
        Transaction::decode(&mut &malformed[..]).unwrap_err(),
        RLPError::Overflow
    );
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
    assert_eq!(buf, vec![0xC7, 0x01, 0x82, 0x0F, 0x0F, 0x82, 0x01, 0x01]);
    assert_eq!(
        Reserved::decode(&mut &buf[..]).expect("Must be decodable"),
        reserved
    );
}

#[test]
fn test_rlp_encode_reserved_unused_2() {
    let reserved = Reserved {
        features: 1,
        unused: vec![Bytes::from(b"\x0F\x0F".to_vec()), Bytes::new()],
    };
    let mut buf = vec![];
    reserved.encode(&mut buf);
    assert_eq!(buf, vec![0xC4, 0x01, 0x82, 0x0F, 0x0F]);
}

#[test]
fn test_rlp_encode_reserved_unused_3() {
    let reserved = Reserved {
        features: 0,
        unused: vec![Bytes::from(b"\x0F\x0F".to_vec()), Bytes::new()],
    };
    let mut buf = vec![];
    reserved.encode(&mut buf);
    assert_eq!(buf, vec![0xC4, 0x80, 0x82, 0x0F, 0x0F]);
}

#[test]
fn test_sign_undelegated() {
    let tx = undelegated_tx!();
    let pk = make_pk!();
    let hash = tx.get_signing_hash();
    assert_eq!(
        hash.to_vec(),
        decode_hex("2a1c25ce0d66f45276a5f308b99bf410e2fc7d5b6ea37a49f2ab9f1da9446478")
    );
    let signature = Transaction::sign_hash(hash, &pk);
    assert_eq!(
        signature.to_vec(),
        decode_hex("f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00")
    );

    let signed = tx.sign(&pk);
    assert_eq!(signed.signature.clone().unwrap(), signature.to_vec());

    let mut buf = vec![];
    signed.encode(&mut buf);
    assert_eq!(
        Transaction::decode(&mut &buf[..]).expect("Must be decodable"),
        signed
    );
    assert!(signed.has_valid_signature());
}

#[test]
fn test_sign_delegated() {
    let tx = delegated_tx!();
    let sender = make_pk!("58e444d4fe08b0f4d9d86ec42f26cf15072af3ddc29a78e33b0ceaaa292bcf6b");
    let gas_payer = make_pk!("0bfd6a863f347f4ef2cf2d09c3db7b343d84bb3e6fc8c201afee62de6381dc65");

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
    let mut buf = vec![];
    tx.encode(&mut buf);
    assert_eq!(
        Transaction::decode(&mut &buf[..]).expect("Must be decodable"),
        tx
    );
    assert!(tx.has_valid_signature());
}

#[test]
fn test_undelegated_signed_properties() {
    let pk = make_pk!();
    let tx = undelegated_tx!().sign(&pk);
    assert_eq!(
        tx.signature.clone().unwrap(),
        decode_hex("f76f3c91a834165872aa9464fc55b03a13f46ea8d3b858e528fcceaf371ad6884193c3f313ff8effbb57fe4d1adc13dceb933bedbf9dbb528d2936203d5511df00"),
    );
    let pubkey = pk.public_key(&Secp256k1::signing_only());
    assert_eq!(tx.origin().unwrap().unwrap(), pubkey);
    assert_eq!(
        tx.id().unwrap().unwrap().to_vec(),
        decode_hex("da90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec")
    );
    assert_eq!(
        &tx.get_delegate_signing_hash(&pubkey.address())[..],
        decode_hex("da90eaea52980bc4bb8d40cb2ff84d78433b3b4a6e7d50b75736c5e3e77b71ec")
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
fn test_delegated_unsigned_properties() {
    let tx = delegated_tx!();
    assert!(tx.is_delegated());
    assert_eq!(tx.signature, None);
    assert_eq!(tx.id(), Ok(None));
    assert_eq!(tx.origin(), Ok(None));
    assert_eq!(tx.delegator(), Ok(None));
}

#[test]
fn test_with_signature_validated() {
    let tx = undelegated_tx!();
    assert_eq!(
        tx.with_signature(Bytes::copy_from_slice(b"\x01\x02\x03")),
        Err(secp256k1::Error::IncorrectSignature)
    );
}

#[test]
fn test_decode_real() {
    let src = decode_hex("f8804a880106f4db1482fd5a81b4e1e09477845a52acad7fe6a346f5b09e5e89e7caec8e3b890391c64cd2bc206c008080828ca08088a63565b632b9b7c3c0b841d76de99625a1a8795e467d509818701ec5961a8a4cf7cc2d75cee95f9ad70891013aaa4088919cc46df4f1e3f87b4ea44d002033fa3f7bd69485cb807aa2985100");
    let tx = Transaction::decode(&mut &src[..]).unwrap();
    let buf = tx.to_broadcastable_bytes().expect("Was signed");
    assert_eq!(buf, src);
}

#[test]
fn test_decode_real_delegated() {
    let src = decode_hex("f9011f27880107b55a710b022420f87ef87c9412e3582d7ca22234f39d2a7be12c98ea9c077e2580b864b391c7d37674686f2d7573640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085bb373400000000000000000000000000000000000000000000000000000000657f828f8180830136798086018c7a1602b1c101b882abd35e0d57fd07462b8517109797bd2608f97a4961d0bb1fbc09d4a2f4983c2230d8a6cb4f3136e49f58eb6d32cf5edad2b0f69af6f0bf767d502a8f5510824101d87ae764add6cddff325122bf5658364fa2a04ad538621bfeb40c56c7185cf28031d9b945e7a124f171daa232499038312de60b3db4cdd6beecde6c8c0c967a100");
    let tx = Transaction::decode(&mut &src[..]).unwrap();
    let mut buf = vec![];
    tx.encode(&mut buf);
    assert_eq!(buf, src);
}

#[test]
fn test_decode_delegated_signature_too_short() {
    let src = decode_hex("f9011e27880107b55a710b022420f87ef87c9412e3582d7ca22234f39d2a7be12c98ea9c077e2580b864b391c7d37674686f2d7573640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085bb373400000000000000000000000000000000000000000000000000000000657f828f8180830136798086018c7a1602b1c101b881abd35e0d57fd07462b8517109797bd2608f97a4961d0bb1fbc09d4a2f4983c2230d8a6cb4f3136e49f58eb6d32cf5edad2b0f69af6f0bf767d502a8f5510824101d87ae764add6cddff325122bf5658364fa2a04ad538621bfeb40c56c7185cf28031d9b945e7a124f171daa232499038312de60b3db4cdd6beecde6c8c0c967a1");
    let tx = Transaction::decode(&mut &src[..]).expect("Should be decodable");
    assert!(!tx.has_valid_signature())
}

#[test]
fn test_decode_delegated_signature_too_long() {
    let src = decode_hex("f9012027880107b55a710b022420f87ef87c9412e3582d7ca22234f39d2a7be12c98ea9c077e2580b864b391c7d37674686f2d7573640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085bb373400000000000000000000000000000000000000000000000000000000657f828f8180830136798086018c7a1602b1c101b883abd35e0d57fd07462b8517109797bd2608f97a4961d0bb1fbc09d4a2f4983c2230d8a6cb4f3136e49f58eb6d32cf5edad2b0f69af6f0bf767d502a8f5510824101d87ae764add6cddff325122bf5658364fa2a04ad538621bfeb40c56c7185cf28031d9b945e7a124f171daa232499038312de60b3db4cdd6beecde6c8c0c967a10101");
    let tx = Transaction::decode(&mut &src[..]).expect("Should be decodable");
    assert!(!tx.has_valid_signature())
}

#[test]
fn test_rlp_decode_address_too_long() {
    let malformed = decode_hex(
        "ec0184aabbccdd20d8d795515167d83b7b8d80addcb281a71d54fc7b3364ffed808081808252088083bc614ec0"
    );
    assert_eq!(
        Transaction::decode(&mut &malformed[..]).unwrap_err(),
        RLPError::ListLengthMismatch {
            expected: 20,
            got: 21
        }
    );
}

#[test]
fn test_rlp_decode_address_startswith_zero_misencoded() {
    let malformed = decode_hex(
        "eb0184aabbccdd20d8d7940067d83b7b8d80addcb281a71d54fc7b3364ffed808081808252088083bc614ec0",
    );
    assert_eq!(
        Transaction::decode(&mut &malformed[..]).unwrap_err(),
        RLPError::LeadingZero
    );
}

#[test]
fn test_rlp_decode_address_shorter() {
    // TODO: test on chain
    let tx = Transaction {
        clauses: vec![Clause {
            to: Some(
                "0x0067d83b7b8d80addcb281a71d54fc7b3364ffed"
                    .parse()
                    .unwrap(),
            ),
            value: 0.into(),
            data: Bytes::new(),
        }],
        ..undelegated_tx!()
    };
    let tx_full = Transaction {
        clauses: vec![Clause {
            to: Some(
                "0x5167d83b7b8d80addcb281a71d54fc7b3364ffed"
                    .parse()
                    .unwrap(),
            ),
            value: 0.into(),
            data: Bytes::new(),
        }],
        ..undelegated_tx!()
    };
    let mut buf = vec![];
    tx.encode(&mut buf);
    assert_eq!(
        Transaction::decode(&mut &buf[..]).expect("Must be decodable"),
        tx
    );

    let mut buf_full = vec![];
    tx_full.encode(&mut buf_full);
    assert_eq!(buf_full.len(), buf.len() + 1);
}

#[test]
fn test_undelegated_malformed_signature_properties() {
    let tx = Transaction {
        signature: Some(Bytes::copy_from_slice(b"\x01\x02\x03")),
        ..undelegated_tx!()
    };
    assert!(!tx.is_delegated());
    assert_eq!(tx.id(), Err(secp256k1::Error::IncorrectSignature));
    assert_eq!(tx.origin(), Err(secp256k1::Error::IncorrectSignature));
    assert_eq!(tx.delegator(), Ok(None));
}

#[test]
fn test_undelegated_malformed_signature_2_properties() {
    let tx = Transaction {
        signature: Some(Bytes::copy_from_slice(&(0..65).collect::<Vec<_>>())),
        ..undelegated_tx!()
    };
    assert!(!tx.is_delegated());
    assert_eq!(tx.id(), Err(secp256k1::Error::InvalidRecoveryId));
    assert_eq!(tx.origin(), Err(secp256k1::Error::InvalidRecoveryId));
    assert_eq!(tx.delegator(), Ok(None));
    assert!(!tx.has_valid_signature());
}

#[test]
fn test_delegated_malformed_signature_properties() {
    let tx = Transaction {
        signature: Some(Bytes::copy_from_slice(b"\x01\x02\x03")),
        ..delegated_tx!()
    };
    assert!(tx.is_delegated());
    assert_eq!(tx.id(), Err(secp256k1::Error::IncorrectSignature));
    assert_eq!(tx.origin(), Err(secp256k1::Error::IncorrectSignature));
    assert_eq!(tx.delegator(), Err(secp256k1::Error::IncorrectSignature));
    assert!(!tx.has_valid_signature());
}

#[test]
fn test_delegated_malformed_signature_2_properties() {
    let tx = Transaction {
        signature: Some(Bytes::copy_from_slice(&(0..65).collect::<Vec<_>>())),
        ..delegated_tx!()
    };
    assert!(tx.is_delegated());
    assert_eq!(tx.id(), Err(secp256k1::Error::IncorrectSignature));
    assert_eq!(tx.origin(), Err(secp256k1::Error::IncorrectSignature));
    assert_eq!(tx.delegator(), Err(secp256k1::Error::IncorrectSignature));
}

#[test]
fn test_delegated_malformed_signature_3_properties() {
    let tx = Transaction {
        signature: Some(Bytes::copy_from_slice(&(0..130).collect::<Vec<_>>())),
        ..delegated_tx!()
    };
    assert!(tx.is_delegated());
    assert_eq!(tx.id(), Err(secp256k1::Error::InvalidRecoveryId));
    assert_eq!(tx.origin(), Err(secp256k1::Error::InvalidRecoveryId));
    assert_eq!(tx.delegator(), Err(secp256k1::Error::InvalidRecoveryId));
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
            value: 0.into(),
            data: Bytes::new(),
        }],
        ..undelegated_tx!()
    };
    assert_eq!(tx.intrinsic_gas(), 53_000);
    let mut buf = vec![];
    tx.encode(&mut buf); // Must not fail
}
