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

    fn existing_tx_id() -> [u8; 32] {
        decode_hex("ea4c3d8b830f777ae55052bd92f2c65ae9f6c36eb391ac52e8e77d5d2bf5f308")
            .try_into()
            .unwrap()
    }
    fn existing_block_id() -> [u8; 32] {
        decode_hex("0107b6875c70deb02eda7a6724891e7774b34b8aecc57d2898f36384c6a6868c")
            .try_into()
            .unwrap()
    }

    fn transaction_details() -> (Transaction, TransactionMeta) {
        let clause_data = b"\xb3\x91\xc7\xd3vtho-usd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\x17\x19\x1a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0e\x7f\x8eJ";
        let signature = b"\xbf3\xd0\0\xd9\xa8\x93\x10\xd4\xda\xddy@\x03\xd5\x1e.\x86\x80\x8b#HQ)\xa4|\xcaE\xf5>Ib_\xd3q>?i\x99\x17X\xc5u\xf7\x12\xc7\xd23\x15\xf6\xe6Z+D\xd3\x19\x0b\xf7\x0c\r=\x85{\xc6\0\x8d5\xb2\xf1\xff\xe2b4\x8d\x17yj\x9a\xc1%\xf8\x9e\xe2b\x83\xa4\xf9F\xb79H\xe6\x80\x11\x1eWTm\x08\x8b\xec\t1\xe3\xae\\7\xae\xe2e\xc9\xaa|\x11L\xfc\x87h\xabi\xe1L\xeez\xdc\x90\xdb\r\xfc\x01";

        let tx = Transaction {
            chain_tag: 39,
            block_ref: 74228606445726694,
            expiration: 32,
            clauses: vec![Clause {
                to: Some(
                    "0x12e3582d7ca22234f39d2a7be12c98ea9c077e25"
                        .parse()
                        .unwrap(),
                ),
                value: 0.into(),
                data: Bytes::copy_from_slice(&clause_data[..]),
            }],
            gas_price_coef: 128,
            gas: 79481,
            depends_on: None,
            nonce: 1702858315418,
            reserved: Some(Reserved {
                features: 1,
                unused: vec![],
            }),
            signature: Some(Bytes::copy_from_slice(&signature[..])),
        };
        let meta = TransactionMeta {
            block_id: "0107b6875c70deb02eda7a6724891e7774b34b8aecc57d2898f36384c6a6868c"
                .from_hex::<Vec<u8>>()
                .unwrap()
                .try_into()
                .unwrap(),
            block_number: 17282695,
            block_timestamp: 1702858320,
        };
        (tx, meta)
    }
    fn block_details() -> (BlockInfo, Vec<BlockTransaction>) {
        let info = BlockInfo {
            number: 17282695,
            id: existing_block_id(),
            size: 655,
            parent_id: decode_hex(
                "0107b686375eabe6821225b0218ef5d51d0933756ca95d558c0a6b010f45f503",
            )
            .try_into()
            .unwrap(),
            timestamp: 1702858320,
            gas_limit: 30000000,
            beneficiary: "0xb4094c25f86d628fdd571afc4077f0d0196afb48"
                .parse()
                .unwrap(),
            gas_used: 37918,
            total_score: 136509202,
            txs_root: decode_hex(
                "0e3d83681601227e22c2eaa3dd5ef1c3301fe23dd7db21ac15984d7b6e2c6552",
            )
            .try_into()
            .unwrap(),
            txs_features: 1,
            state_root: decode_hex(
                "dc94484d4f0d01b068dc1d66c5731dd36b32ba3b08bcfad977d599e5c9342dd1",
            )
            .try_into()
            .unwrap(),
            receipts_root: decode_hex(
                "df5066746c62904390f2312e81fb7a98811098627a2ae8474457e69cd60b846a",
            )
            .try_into()
            .unwrap(),
            com: true,
            signer: "0x0771bc0fe8b6dcf72372440c79a309e92ffb93e8"
                .parse()
                .unwrap(),
            is_trunk: true,
            is_finalized: true,
        };
        let clause_data= b"\xb3\x91\xc7\xd3vtho-usd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\x17\x19\x1a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0e\x7f\x8eJ";
        let exec_data= b"vtho-usd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\x17\x19\x1a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0e\x7f\x8eJ";
        let transaction = BlockTransaction {
            transaction: ExtendedTransaction {
                id: [
                    234, 76, 61, 139, 131, 15, 119, 122, 229, 80, 82, 189, 146, 242, 198, 90, 233,
                    246, 195, 110, 179, 145, 172, 82, 232, 231, 125, 93, 43, 245, 243, 8,
                ],
                origin: "0x56cb0e0276ad689cc68954d47460cd70f46244dc"
                    .parse()
                    .unwrap(),
                delegator: Some(
                    "0xeedfd966da350803ba7fc8f40f6a3151164e2058"
                        .parse()
                        .unwrap(),
                ),
                size: 290,
                chain_tag: 39,
                block_ref: 74228606445726694,
                expiration: 32,
                clauses: vec![Clause {
                    to: Some(
                        "0x12e3582d7ca22234f39d2a7be12c98ea9c077e25"
                            .parse()
                            .unwrap(),
                    ),
                    value: 0.into(),
                    data: Bytes::copy_from_slice(clause_data),
                }],
                gas_price_coef: 128,
                gas: 79481,
                depends_on: None,
                nonce: 1702858315418,
            },
            receipt: Receipt {
                gas_used: 37918,
                gas_payer: "0xeedfd966da350803ba7fc8f40f6a3151164e2058"
                    .parse()
                    .unwrap(),
                paid: 569513490196068766_u128.into(),
                reward: 170854047058820629_u128.into(),
                reverted: false,
                outputs: vec![ReceiptOutput {
                    contract_address: None,
                    events: vec![Event {
                        address: "0x12e3582d7ca22234f39d2a7be12c98ea9c077e25"
                            .parse()
                            .unwrap(),
                        topics: vec![[
                            239, 200, 244, 4, 28, 11, 164, 208, 151, 229, 75, 206, 126, 91, 196,
                            126, 197, 180, 92, 2, 112, 196, 35, 121, 196, 182, 145, 200, 89, 67,
                            237, 240,
                        ]],
                        data: Bytes::copy_from_slice(exec_data),
                    }],
                    transfers: vec![],
                }],
            },
        };
        (info, vec![transaction])
    }

    #[tokio::test]
    async fn test_fetch_existing() {
        let client = ThorNode::testnet();
        let (tx, meta) = client
            .fetch_transaction(existing_tx_id())
            .await
            .unwrap()
            .expect("Must be found");
        let (tx_expected, meta_expected) = transaction_details();
        assert_eq!(tx, tx_expected);
        assert_eq!(meta.expect("Meta should be found"), meta_expected);
    }

    #[tokio::test]
    async fn test_fetch_existing_ext() {
        let client = ThorNode::testnet();
        let (tx, meta) = client
            .fetch_extended_transaction(existing_tx_id())
            .await
            .unwrap()
            .expect("Must be found");
        let (tx_expected, meta_expected) = transaction_details();
        let Transaction {
            chain_tag,
            block_ref,
            expiration,
            clauses,
            gas_price_coef,
            gas,
            depends_on,
            nonce,
            ..
        } = tx_expected.clone();
        assert_eq!(
            tx,
            ExtendedTransaction {
                chain_tag,
                block_ref,
                expiration,
                clauses,
                gas_price_coef,
                gas,
                depends_on,
                nonce,
                size: 290,
                delegator: Some(
                    "0xeedfd966da350803ba7fc8f40f6a3151164e2058"
                        .parse()
                        .unwrap()
                ),
                id: existing_tx_id(),
                origin: "0x56cb0e0276ad689cc68954d47460cd70f46244dc"
                    .parse()
                    .unwrap()
            }
        );
        assert_eq!(
            tx.as_transaction(),
            Transaction {
                signature: None,
                ..tx_expected
            }
        );
        assert_eq!(meta.expect("Meta should be found"), meta_expected);
    }

    #[tokio::test]
    async fn test_fetch_existing_receipt() {
        let client = ThorNode::testnet();
        let (receipt, meta) = client
            .fetch_transaction_receipt(existing_tx_id())
            .await
            .expect("Must not fail")
            .expect("Must have been found");
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
        };
        let expected_meta = ReceiptMeta {
            block_id: [
                1, 7, 182, 135, 92, 112, 222, 176, 46, 218, 122, 103, 36, 137, 30, 119, 116, 179,
                75, 138, 236, 197, 125, 40, 152, 243, 99, 132, 198, 166, 134, 140,
            ],
            block_number: 17282695,
            block_timestamp: 1702858320,
            tx_id: [
                234, 76, 61, 139, 131, 15, 119, 122, 229, 80, 82, 189, 146, 242, 198, 90, 233, 246,
                195, 110, 179, 145, 172, 82, 232, 231, 125, 93, 43, 245, 243, 8,
            ],
            tx_origin: "0x56cb0e0276ad689cc68954d47460cd70f46244dc"
                .parse()
                .unwrap(),
        };
        assert_eq!(receipt, expected);
        assert_eq!(meta, expected_meta);
    }

    #[tokio::test]
    async fn test_fetch_existing_receipt_with_transfers() {
        let client = ThorNode::mainnet();
        let (receipt, meta) = client
            .fetch_transaction_receipt(
                decode_hex("1755319a898a52fbceb4c58f51d63e6fa53592678512dd786de953d55895946a")
                    .try_into()
                    .unwrap(),
            )
            .await
            .expect("Must not fail")
            .expect("Must have been found");
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
        };
        let expected_meta = ReceiptMeta {
            block_id: [
                1, 7, 123, 88, 83, 194, 165, 215, 242, 232, 190, 239, 4, 90, 10, 32, 219, 20, 208,
                49, 108, 178, 89, 39, 71, 129, 5, 138, 112, 103, 10, 247,
            ],
            block_number: 17267544,
            block_timestamp: 1703201660,
            tx_id: [
                23, 85, 49, 154, 137, 138, 82, 251, 206, 180, 197, 143, 81, 214, 62, 111, 165, 53,
                146, 103, 133, 18, 221, 120, 109, 233, 83, 213, 88, 149, 148, 106,
            ],
            tx_origin: "0xb0c224a96655ba8d51f35f98068f5fc12f930946"
                .parse()
                .unwrap(),
        };
        assert_eq!(receipt, expected);
        assert_eq!(meta, expected_meta);
    }

    #[tokio::test]
    async fn test_fetch_block() {
        let client = ThorNode::testnet();
        let (blockinfo, transactions) = client
            .fetch_block(BlockReference::ID(
                decode_hex("0107b6875c70deb02eda7a6724891e7774b34b8aecc57d2898f36384c6a6868c")
                    .try_into()
                    .unwrap(),
            ))
            .await
            .expect("Must not fail")
            .expect("Must have been found");

        let (expected_info, expected_transactions) = block_details();
        let expected_transactions: Vec<_> = expected_transactions
            .into_iter()
            .map(|t| t.transaction.id)
            .collect();
        assert_eq!(blockinfo, expected_info);
        assert_eq!(transactions, expected_transactions);
    }

    #[tokio::test]
    async fn test_fetch_block_by_number() {
        let client = ThorNode::testnet();
        let (blockinfo, transactions) = client
            .fetch_block(BlockReference::Number(0x0107b687))
            .await
            .expect("Must not fail")
            .expect("Must have been found");

        let (expected_info, expected_transactions) = block_details();
        let expected_transactions: Vec<_> = expected_transactions
            .into_iter()
            .map(|t| t.transaction.id)
            .collect();
        assert_eq!(blockinfo, expected_info);
        assert_eq!(transactions, expected_transactions);
    }

    #[tokio::test]
    async fn test_fetch_block_latest() {
        let client = ThorNode::testnet();
        let res = client
            .fetch_block(BlockReference::Best)
            .await
            .expect("Must not fail");
        assert!(res.is_some());
    }

    #[tokio::test]
    async fn test_fetch_block_finalized() {
        let client = ThorNode::testnet();
        let res = client
            .fetch_block(BlockReference::Finalized)
            .await
            .expect("Must not fail");
        assert!(res.is_some());
    }

    #[tokio::test]
    async fn test_fetch_block_expanded() {
        let client = ThorNode::testnet();
        let (blockinfo, transactions) = client
            .fetch_block_expanded(BlockReference::ID(existing_block_id()))
            .await
            .expect("Must not fail")
            .expect("Must have been found");

        let (expected_info, expected_transactions) = block_details();
        assert_eq!(blockinfo, expected_info);
        assert_eq!(transactions, expected_transactions);
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
    async fn test_fetch_nonexisting_ext() {
        let client = ThorNode::testnet();
        let result = client
            .fetch_extended_transaction(
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

    #[tokio::test]
    async fn test_fetch_nonexisting_block() {
        let client = ThorNode::testnet();
        let result = client
            .fetch_block(BlockReference::ID(
                decode_hex("0107b6875c70deb02eda7a6724891e7774b34b8aecc57d2898f36384c6a6868d")
                    .try_into()
                    .unwrap(),
            ))
            .await
            .expect("Must not fail");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_fetch_nonexisting_block_ext() {
        let client = ThorNode::testnet();
        let result = client
            .fetch_block_expanded(BlockReference::ID(
                decode_hex("0107b6875c70deb02eda7a6724891e7774b34b8aecc57d2898f36384c6a6868d")
                    .try_into()
                    .unwrap(),
            ))
            .await
            .expect("Must not fail");
        assert!(result.is_none());
    }
}
