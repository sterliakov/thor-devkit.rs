//! thor-devkit does not vendor ABI parsing solution, because a good one
//! already exists in wild ([`ethabi`](https://docs.rs/ethabi/latest/ethabi/index.html)).
//!
//! To decode or encode data given a contract ABI and some input data,
//! you can create a contract from JSON ABI specification and process it
//! as necessary.
//!
//! Future version of thor-devkit will likely depend on [`ethabi`] to improve
//! interoperability and enable more smooth experience.

use ethabi::{Contract, Token};
use std::fs::File;
use thor_devkit::rlp::Bytes;

fn demo_abi() {
    let eip20 = Contract::load(File::open("data/eip20.abi").expect("Must exist"))
        .expect("Should be loadable");
    let owner = [0u8; 20];
    let spender = [1u8; 20];
    let inputs = vec![Token::Address(owner.into()), Token::Address(spender.into())];
    let allowance = eip20.function("allowance").expect("Exists");
    println!("Function signature: {}", allowance.signature());
    println!(
        "Function short signature: {:02x?}",
        allowance.short_signature()
    );
    let encoded = allowance
        .encode_input(&inputs)
        .expect("Should be encodable");
    println!(
        "Encoded data for allowance call: {:x}",
        Bytes::copy_from_slice(&encoded[..])
    );
    // To decode, we strip a function signature first:
    let decoded = allowance.decode_input(&encoded[4..]).expect("Should parse");
    assert_eq!(decoded, inputs);

    let decoded_out = allowance.decode_output(&[0x01; 32]).expect("Should parse");
    assert_eq!(decoded_out, vec![Token::Uint([0x01; 32].into())])
}

#[test]
fn test_run() {
    demo_abi();
}

fn main() {
    demo_abi();
}
