//! thor-devkit does not vendor ABI parsing solution, because a good one
//! already exists in wild ([`alloy`](https://docs.rs/crate/alloy/latest)).
//!
//! To decode or encode data given a contract ABI and some input data,
//! you can create a contract from JSON ABI specification and process it
//! as necessary.
//!
//! Future version of thor-devkit will likely depend on [`alloy`] to improve
//! interoperability and enable more smooth experience.

use alloy::dyn_abi::{DynSolValue, FunctionExt, JsonAbiExt};
use alloy::json_abi::JsonAbi;
use alloy::primitives::U256;
use thor_devkit::rlp::Bytes;

fn demo_abi() {
    let code = std::fs::read_to_string("data/eip20.abi").expect("Must exist");
    let eip20: JsonAbi = serde_json::from_str(&code).expect("Should be loadable");
    let owner = [0u8; 20];
    let spender = [1u8; 20];
    let inputs = vec![
        DynSolValue::Address(owner.into()),
        DynSolValue::Address(spender.into()),
    ];
    let allowance = {
        let all_found = eip20.function("allowance").expect("Exists");
        assert!(all_found.len() == 1);
        &all_found[0]
    };
    println!("Function signature: {}", allowance.full_signature());
    println!("Function selector: {:02x?}", allowance.selector());
    let encoded = allowance
        .abi_encode_input(&inputs)
        .expect("Should be encodable");
    println!(
        "Encoded data for allowance call: {:x}",
        Bytes::copy_from_slice(&encoded[..])
    );
    // To decode, we strip a function signature first:
    let decoded = allowance
        .abi_decode_input(&encoded[4..])
        .expect("Should parse");
    assert_eq!(decoded, inputs);

    let decoded_out = allowance
        .abi_decode_output(&[0x01; 32])
        .expect("Should parse");
    assert_eq!(
        decoded_out,
        vec![DynSolValue::Uint(U256::from_be_bytes([0x01u8; 32]), 256)]
    )
}

#[test]
fn test_run() {
    demo_abi();
}

fn main() {
    demo_abi();
}
