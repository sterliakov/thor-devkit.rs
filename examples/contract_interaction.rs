//! Network communication requires `http` create feature.
//! Transaction builder requires additionally `builder` feature.
//!
//! This example shows a contract interaction based on VTHO contract.

use alloy::dyn_abi::{DynSolValue, FunctionExt, JsonAbiExt};
use alloy::json_abi::{Function, JsonAbi};
use alloy::primitives::U256;
use std::{thread, time::Duration};
use thor_devkit::hdnode::{HDNode, Language, Mnemonic};
use thor_devkit::network::{AResult, BlockReference, ThorNode};
use thor_devkit::transactions::{Clause, Transaction};
use thor_devkit::Address;

const CONTRACT_ADDRESS: &str = "0x0000000000000000000000000000456E65726779";

async fn get_balance(
    node: &ThorNode,
    balance_of: &Function,
    user: &Address,
) -> Result<U256, String> {
    let data = balance_of
        .abi_encode_input(&[DynSolValue::Address(**user)])
        .expect("Input valid");
    let clause = Clause {
        to: Some(CONTRACT_ADDRESS.parse().unwrap()),
        data: data.into(),
        value: U256::ZERO,
    };
    let result = node
        .eth_call(clause, BlockReference::Best)
        .await
        .map_err(|_| "Failed to perform eth_call")?;

    let parsed_output = balance_of
        .abi_decode_output(&result)
        .map_err(|_| "Failed to decode outputs")?;
    assert!(parsed_output.len() == 1, "Must be single output");
    match parsed_output[0] {
        DynSolValue::Uint(balance, _) => Ok(balance),
        _ => Err("Unexpected output".to_string()),
    }
}

async fn create_and_broadcast_transaction() -> AResult<()> {
    let code = std::fs::read_to_string("data/energy.abi").expect("Must exist");
    let abi: JsonAbi = serde_json::from_str(&code).expect("Should be loadable");

    let transfer = &abi.function("transfer").expect("Exists")[0];
    let balance_of = &abi.function("balanceOf").expect("Exists")[0];

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
        .abi_encode_input(&[
            DynSolValue::Address(*recipient),
            DynSolValue::Uint(U256::ONE, 256),
        ])
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
        recipient_after == recipient_before + U256::ONE,
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
