//! Network communication requires `http` create feature.
//! Transaction builder requires additionally `builder` feature.

use std::{thread, time::Duration};
use thor_devkit::hdnode::{HDNode, Language, Mnemonic};
use thor_devkit::network::{AResult, ThorNode};
use thor_devkit::transactions::Transaction;
use thor_devkit::{Address, U256};

async fn create_and_broadcast_transaction() -> AResult<()> {
    let node = ThorNode::testnet();
    let recipient: Address = std::env::var("TEST_TO_ADDRESS")
        .expect("Address must be provided")
        .parse()
        .unwrap();
    let amount = 10;
    let transaction = Transaction::build(node.clone())
        .gas_price_coef(128)
        .add_transfer(recipient, amount)
        .build()
        .await?;
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
    let sender_before = node.fetch_account(sender).await?.balance;
    let recipient_before = node.fetch_account(recipient).await?.balance;
    println!(
        "Balances before: {:?}, {:?}",
        sender_before, recipient_before
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
    let sender_after = node.fetch_account(sender).await?.balance;
    let recipient_after = node.fetch_account(recipient).await?.balance;
    println!("Balances after: {:?}, {:?}", sender_after, recipient_after);
    assert_eq!(sender_before - sender_after, U256::from(amount));
    assert_eq!(recipient_after - recipient_before, U256::from(amount));
    Ok(())
}

#[tokio::main]
async fn main() {
    create_and_broadcast_transaction()
        .await
        .expect("Must not fail");
}
