#[cfg(feature = "builder")]
#[cfg(test)]
mod test_builder {
    use thor_devkit::network::*;
    use thor_devkit::rlp::Bytes;
    use thor_devkit::transactions::{Clause, Reserved, Transaction, TransactionBuilder};
    use thor_devkit::{Address, U256};

    #[tokio::test]
    async fn test_minimal() {
        let addr = Address::from([0; 20]);
        let mut tx = TransactionBuilder::new(ThorNode::testnet())
            .add_transfer(addr, 1000)
            .build()
            .await
            .expect("Must build");
        tx.block_ref = 1;
        tx.nonce = 1;
        assert_eq!(
            tx,
            Transaction {
                chain_tag: ThorNode::TESTNET_CHAIN_TAG,
                block_ref: 1,
                expiration: 128,
                clauses: vec![Clause {
                    to: Some(addr),
                    value: U256::from(1000),
                    data: Bytes::new()
                }],
                gas_price_coef: 0,
                gas: 21_000,
                depends_on: None,
                nonce: 1,
                reserved: None,
                signature: None,
            }
        )
    }

    #[tokio::test]
    async fn test_multiple_clauses() {
        let addr = Address::from([0; 20]);
        let mut tx = TransactionBuilder::new(ThorNode::testnet())
            .add_transfer(addr, 1000u64)
            .add_transfer(addr, 5000u64)
            .build()
            .await
            .expect("Must build");
        tx.block_ref = 1;
        tx.nonce = 1;
        assert_eq!(
            tx,
            Transaction {
                chain_tag: ThorNode::TESTNET_CHAIN_TAG,
                block_ref: 1,
                expiration: 128,
                clauses: vec![
                    Clause {
                        to: Some(addr),
                        value: U256::from(1000),
                        data: Bytes::new()
                    },
                    Clause {
                        to: Some(addr),
                        value: U256::from(5000),
                        data: Bytes::new()
                    },
                ],
                gas_price_coef: 0,
                gas: 37_000,
                depends_on: None,
                nonce: 1,
                reserved: None,
                signature: None,
            }
        )
    }

    #[tokio::test]
    async fn test_all_parameters() {
        let addr = Address::from([0; 20]);
        let tx = TransactionBuilder::new(ThorNode::testnet())
            .delegated()
            .nonce(1234)
            .depends_on(U256::from(0x1234))
            .gas(56_000)
            .gas_price_coef(128)
            .expiration(32)
            .block_ref(0xaaaa)
            .add_transfer(addr, 1000)
            .build()
            .await
            .expect("Must build");
        assert_eq!(
            tx,
            Transaction {
                chain_tag: ThorNode::TESTNET_CHAIN_TAG,
                block_ref: 0xaaaa,
                expiration: 32,
                clauses: vec![Clause {
                    to: Some(addr),
                    value: U256::from(1000),
                    data: Bytes::new()
                }],
                gas_price_coef: 128,
                gas: 56_000,
                depends_on: Some(U256::from(0x1234)),
                nonce: 1234,
                reserved: Some(Reserved::new_delegated()),
                signature: None,
            }
        )
    }

    #[tokio::test]
    async fn test_requires_clauses() {
        let err = TransactionBuilder::new(ThorNode::testnet())
            .build()
            .await
            .expect_err("Must fail");
        assert_eq!(
            format!("{}", err),
            "Cannot build an empty transaction - make sure to add at least one clause first."
        )
    }

    #[tokio::test]
    async fn test_requires_gas_for_contract() {
        let err = TransactionBuilder::new(ThorNode::testnet())
            .add_contract_create(vec![0x12].into())
            .build()
            .await
            .expect_err("Must fail");
        assert_eq!(
            format!("{}", err),
            "Transaction clauses involve contract interaction, please provide gas amount explicitly."
        )
    }

    #[tokio::test]
    async fn test_allows_manual_gas_for_contract_create() {
        let tx = TransactionBuilder::new(ThorNode::testnet())
            .add_contract_create(vec![0x12].into())
            .gas(85_000)
            .block_ref(1)
            .nonce(1)
            .build()
            .await
            .expect("Must not fail");
        assert_eq!(
            tx,
            Transaction {
                chain_tag: ThorNode::TESTNET_CHAIN_TAG,
                block_ref: 1,
                expiration: 128,
                clauses: vec![Clause {
                    to: None,
                    value: U256::ZERO,
                    data: vec![0x12].into(),
                }],
                gas_price_coef: 0,
                gas: 85_000,
                depends_on: None,
                nonce: 1,
                reserved: None,
                signature: None,
            }
        );
    }

    #[tokio::test]
    async fn test_allows_manual_gas_for_contract_call() {
        let addr = Address::from([0x01; 20]);
        let tx = TransactionBuilder::new(ThorNode::testnet())
            .add_contract_call(addr, vec![0x12].into())
            .gas(85_000)
            .block_ref(1)
            .nonce(1)
            .build()
            .await
            .expect("Must not fail");
        assert_eq!(
            tx,
            Transaction {
                chain_tag: ThorNode::TESTNET_CHAIN_TAG,
                block_ref: 1,
                expiration: 128,
                clauses: vec![Clause {
                    to: Some(addr),
                    value: U256::ZERO,
                    data: vec![0x12].into(),
                }],
                gas_price_coef: 0,
                gas: 85_000,
                depends_on: None,
                nonce: 1,
                reserved: None,
                signature: None,
            }
        );
    }
}
