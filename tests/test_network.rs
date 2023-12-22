use rustc_hex::FromHex;

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.from_hex().unwrap()
}

#[cfg(feature = "http")]
#[cfg(test)]
mod test_network {
    use super::*;
    use thor_devkit::network::*;
    use thor_devkit::rlp::Bytes;
    use thor_devkit::transactions::*;

    #[tokio::test]
    async fn test_fetch_existing() {
        let client = ThorNode::testnet();
        let (tx, meta) = client
            .fetch_transaction(
                decode_hex("ea4c3d8b830f777ae55052bd92f2c65ae9f6c36eb391ac52e8e77d5d2bf5f308")
                    .try_into()
                    .unwrap(),
            )
            .await
            .unwrap()
            .expect("Must be found");
        let clause_data = b"\xb3\x91\xc7\xd3vtho-usd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\x17\x19\x1a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0e\x7f\x8eJ";
        let signature =b"\xbf3\xd0\0\xd9\xa8\x93\x10\xd4\xda\xddy@\x03\xd5\x1e.\x86\x80\x8b#HQ)\xa4|\xcaE\xf5>Ib_\xd3q>?i\x99\x17X\xc5u\xf7\x12\xc7\xd23\x15\xf6\xe6Z+D\xd3\x19\x0b\xf7\x0c\r=\x85{\xc6\0\x8d5\xb2\xf1\xff\xe2b4\x8d\x17yj\x9a\xc1%\xf8\x9e\xe2b\x83\xa4\xf9F\xb79H\xe6\x80\x11\x1eWTm\x08\x8b\xec\t1\xe3\xae\\7\xae\xe2e\xc9\xaa|\x11L\xfc\x87h\xabi\xe1L\xeez\xdc\x90\xdb\r\xfc\x01";
        assert_eq!(
            tx,
            Transaction {
                chain_tag: 39,
                block_ref: 74228606445726694,
                expiration: 32,
                clauses: vec![Clause {
                    to: Some(
                        "0x12e3582d7ca22234f39d2a7be12c98ea9c077e25"
                            .parse()
                            .unwrap()
                    ),
                    value: 0.into(),
                    data: Bytes::copy_from_slice(&clause_data[..])
                }],
                gas_price_coef: 128,
                gas: 79481,
                depends_on: None,
                nonce: 1702858315418,
                reserved: Some(Reserved {
                    features: 1,
                    unused: vec![]
                }),
                signature: Some(Bytes::copy_from_slice(&signature[..])),
            }
        );
        assert_eq!(
            meta.expect("Meta should be found"),
            TransactionMeta {
                block_id: "0107b6875c70deb02eda7a6724891e7774b34b8aecc57d2898f36384c6a6868c"
                    .from_hex::<Vec<u8>>()
                    .unwrap()
                    .try_into()
                    .unwrap(),
                block_number: 17282695,
                block_timestamp: 1702858320,
            }
        );
    }

    #[tokio::test]
    async fn test_fetch_existing_receipt() {
        let client = ThorNode::testnet();
        let receipt = client
            .fetch_transaction_receipt(
                decode_hex("ea4c3d8b830f777ae55052bd92f2c65ae9f6c36eb391ac52e8e77d5d2bf5f308")
                    .try_into()
                    .unwrap(),
            )
            .await
            .unwrap();
        let clause_data = b"vtho-usd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\x17\x19\x1a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0e\x7f\x8eJ";
        let expected = Receipt {
            gas_used: 37918,
            gas_payer: "0xeedfd966da350803ba7fc8f40f6a3151164e2058"
                .parse()
                .unwrap(),
            paid: 569513490196068766_u64.into(),
            reward: 170854047058820629_u64.into(),
            reverted: false,
            outputs: vec![ReceiptOutput {
                contract_address: None,
                events: vec![Event {
                    address: "0x12e3582d7ca22234f39d2a7be12c98ea9c077e25"
                        .parse()
                        .unwrap(),
                    topics: vec![[
                        239, 200, 244, 4, 28, 11, 164, 208, 151, 229, 75, 206, 126, 91, 196, 126,
                        197, 180, 92, 2, 112, 196, 35, 121, 196, 182, 145, 200, 89, 67, 237, 240,
                    ]],
                    data: Bytes::copy_from_slice(&clause_data[..]),
                }],
                transfers: vec![],
            }],
            meta: ReceiptMeta {
                block_id: [
                    1, 7, 182, 135, 92, 112, 222, 176, 46, 218, 122, 103, 36, 137, 30, 119, 116,
                    179, 75, 138, 236, 197, 125, 40, 152, 243, 99, 132, 198, 166, 134, 140,
                ],
                block_number: 17282695,
                block_timestamp: 1702858320,
                tx_id: [
                    234, 76, 61, 139, 131, 15, 119, 122, 229, 80, 82, 189, 146, 242, 198, 90, 233,
                    246, 195, 110, 179, 145, 172, 82, 232, 231, 125, 93, 43, 245, 243, 8,
                ],
                tx_origin: "0x56cb0e0276ad689cc68954d47460cd70f46244dc"
                    .parse()
                    .unwrap(),
            },
        };
        assert_eq!(receipt.unwrap(), expected)
    }

    #[tokio::test]
    async fn test_fetch_existing_receipt_with_transfers() {
        let client = ThorNode::mainnet();
        let receipt = client
            .fetch_transaction_receipt(
                decode_hex("1755319a898a52fbceb4c58f51d63e6fa53592678512dd786de953d55895946a")
                    .try_into()
                    .unwrap(),
            )
            .await
            .unwrap();
        let expected = Receipt {
            gas_used: 21000,
            gas_payer: "0xb0c224a96655ba8d51f35f98068f5fc12f930946"
                .parse()
                .unwrap(),
            paid: 210000000000000000_u64.into(),
            reward: 63000000000000000_u64.into(),
            reverted: false,
            outputs: vec![ReceiptOutput {
                contract_address: None,
                events: vec![],
                transfers: vec![Transfer {
                    sender: "0xb0c224a96655ba8d51f35f98068f5fc12f930946"
                        .parse()
                        .unwrap(),
                    recipient: "0xfe33b406664f7cc03ede326e695c06c211a45a48"
                        .parse()
                        .unwrap(),
                    amount: 5733123118820000000000_u128.into(),
                }],
            }],
            meta: ReceiptMeta {
                block_id: [
                    1, 7, 123, 88, 83, 194, 165, 215, 242, 232, 190, 239, 4, 90, 10, 32, 219, 20,
                    208, 49, 108, 178, 89, 39, 71, 129, 5, 138, 112, 103, 10, 247,
                ],
                block_number: 17267544,
                block_timestamp: 1703201660,
                tx_id: [
                    23, 85, 49, 154, 137, 138, 82, 251, 206, 180, 197, 143, 81, 214, 62, 111, 165,
                    53, 146, 103, 133, 18, 221, 120, 109, 233, 83, 213, 88, 149, 148, 106,
                ],
                tx_origin: "0xb0c224a96655ba8d51f35f98068f5fc12f930946"
                    .parse()
                    .unwrap(),
            },
        };
        assert_eq!(receipt.expect("Must be found"), expected)
    }

    #[tokio::test]
    async fn test_fetch_nonexisting() {
        let client = ThorNode::testnet();
        let result = client
            .fetch_transaction(
                decode_hex("ea0c3d8b830f777ae55052bd92f2c65ae9f6c36eb391ac52e8e77d5d2bf5f308")
                    .try_into()
                    .unwrap(),
            )
            .await
            .expect("Must not fail");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_fetch_nonexisting_receipt() {
        let client = ThorNode::testnet();
        let result = client
            .fetch_transaction_receipt(
                decode_hex("ea0c3d8b830f777ae55052bd92f2c65ae9f6c36eb391ac52e8e77d5d2bf5f308")
                    .try_into()
                    .unwrap(),
            )
            .await
            .expect("Must not fail");
        assert!(result.is_none());
    }
}
