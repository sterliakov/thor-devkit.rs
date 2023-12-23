//! Network communication requires `http` create feature.

use std::{thread, time::Duration};
use thor_devkit::hdnode::{HDNode, Language, Mnemonic};
use thor_devkit::network::{AResult, BlockReference, ThorNode};
use thor_devkit::transactions::{Clause, Transaction};
use thor_devkit::Address;

async fn create_and_broadcast_transaction() -> AResult<()> {
    let node = ThorNode::testnet();
    let block_ref = node
        .fetch_block(BlockReference::Best)
        .await?
        .expect("Must exist")
        .0
        .id
        .0[3];
    let recipient: Address = std::env::var("TEST_TO_ADDRESS")
        .expect("Address must be provided")
        .parse()
        .unwrap();
    let transaction = Transaction {
        chain_tag: node.chain_tag,
        block_ref: block_ref,
        expiration: 128,
        clauses: vec![Clause {
            to: Some(recipient),
            value: 1000.into(),
            data: b"".to_vec().into(),
        }],
        gas_price_coef: 128,
        gas: 21000,
        depends_on: None,
        nonce: 0xbc614e,
        reserved: None,
        signature: None,
    };
    let mnemonic = Mnemonic::from_phrase(
        &std::env::var("TEST_MNEMONIC").expect("Mnemonic must be provided"),
        Language::English,
    )?;
    let wallet = HDNode::build().mnemonic(mnemonic).build()?.derive(0)?;
    let sender = wallet.address();
    println!(
        "Sending from {:?} to {:?}",
        sender.to_checksum_address(),
        recipient.to_checksum_address()
    );
    println!(
        "Balances before: {:?}, {:?}",
        node.fetch_account(sender).await?.balance,
        node.fetch_account(recipient).await?.balance
    );
    let signed = transaction.sign(&wallet.private_key()?.private_key());
    let id = node.broadcast_transaction(&signed).await?;
    loop {
        if let Some((_, tx_meta)) = node.fetch_extended_transaction(id).await? {
            if let Some(meta) = tx_meta {
                println!("Transaction included into block {:064x}", meta.block_id);
                break;
            } else {
                println!("Transaction not finalized yet");
            }
        } else {
            println!("Transaction not processed yet");
            thread::sleep(Duration::from_secs(2));
        }
    }
    println!(
        "Balances after: {:?}, {:?}",
        node.fetch_account(sender).await?.balance,
        node.fetch_account(recipient).await?.balance
    );
    Ok(())
}

#[tokio::test]
async fn test_run() {
    create_and_broadcast_transaction()
        .await
        .expect("Must not fail");
}

#[tokio::main]
async fn main() {
    create_and_broadcast_transaction()
        .await
        .expect("Must not fail");
}
