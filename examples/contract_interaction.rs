//! Network communication requires `http` create feature.
//! Transaction builder requires additionally `builder` feature.
//!
//! This example shows a contract interaction based on VTHO contract.

use ethabi::{Contract, Function, Token};
use std::{fs::File, ops::Deref, thread, time::Duration};
use thor_devkit::hdnode::{HDNode, Language, Mnemonic};
use thor_devkit::network::{AResult, BlockReference, ThorNode};
use thor_devkit::transactions::{Clause, Transaction};
use thor_devkit::{Address, U256};

const CONTRACT_ADDRESS: &str = "0x0000000000000000000000000000456E65726779";

async fn get_balance(
    node: &ThorNode,
    balance_of: &Function,
    user: &Address,
) -> Result<U256, String> {
    let data = balance_of
        .encode_input(&[Token::Address(*user.deref())])
        .expect("Input valid");
    let clause = Clause {
        to: Some(CONTRACT_ADDRESS.parse().unwrap()),
        data: data.into(),
        value: 0.into(),
    };
    let result = node
        .eth_call(clause, BlockReference::Best)
        .await
        .map_err(|_| "Failed to perform eth_call")?;

    let parsed_output = balance_of
        .decode_output(&result)
        .map_err(|_| "Failed to decode outputs")?;
    assert!(parsed_output.len() == 1, "Must be single output");
    match parsed_output[0] {
        Token::Uint(balance) => Ok(balance),
        _ => Err("Unexpected output".to_string()),
    }
}

async fn create_and_broadcast_transaction() -> AResult<()> {
    let abi = Contract::load(File::open("data/energy.abi").expect("Must exist"))
        .expect("Should be loadable");

    let transfer = abi.function("transfer").expect("Exists");
    let balance_of = abi.function("balanceOf").expect("Exists");

    let node = ThorNode::testnet();
    let mnemonic = Mnemonic::from_phrase(
        &std::env::var("TEST_MNEMONIC").expect("Mnemonic must be provided"),
        Language::English,
    )?;
    let wallet = HDNode::build().mnemonic(mnemonic).build()?.derive(0)?;
    let sender = wallet.address();
    let recipient: Address = std::env::var("TEST_TO_ADDRESS")
        .expect("Address must be provided")
        .parse()
        .unwrap();

    let sender_before = get_balance(&node, balance_of, &sender)
        .await
        .expect("Failed to get balance");
    let recipient_before = get_balance(&node, balance_of, &recipient)
        .await
        .expect("Failed to get balance");
    println!(
        "Balances before: {:?}, {:?}",
        sender_before, recipient_before
    );

    let data = transfer
        .encode_input(&[Token::Address(*recipient.deref()), Token::Uint(U256::one())])
        .expect("Should be encodable");
    let transaction = Transaction::build(node.clone())
        .gas_price_coef(128)
        .add_contract_call(CONTRACT_ADDRESS.parse().unwrap(), data.into())
        .gas(56_000)
        .build()
        .await?;
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

    let sender_after = get_balance(&node, balance_of, &sender)
        .await
        .expect("Failed to get balance");
    let recipient_after = get_balance(&node, balance_of, &recipient)
        .await
        .expect("Failed to get balance");
    println!("Balances after: {:?}, {:?}", sender_after, recipient_after);
    assert!(
        recipient_after == recipient_before + 1,
        "Transfer unsuccessful"
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    create_and_broadcast_transaction()
        .await
        .expect("Must not fail");
}
