use itertools::Itertools;
use rand::RngCore;
use secp256k1::Secp256k1;
use thor_devkit::hdnode::{HDNode, Language, Mnemonic};
use thor_devkit::AddressConvertible;

fn create_wallet() {
    let mut entropy = [0u8; 32];
    rand::rng().fill_bytes(&mut entropy);
    let mnemonic =
        Mnemonic::from_entropy(&entropy, Language::English).expect("Should be constructible");
    println!("Mnemonic text: {}", mnemonic.clone().into_phrase());
    let node = HDNode::build()
        .mnemonic(mnemonic)
        .build()
        .expect("Should build");
    let priv_key = node.private_key().unwrap().private_key().clone();
    println!(
        "Private key: {}",
        priv_key
            .secret_bytes()
            .iter()
            .map(|&c| format!("{:02x}", c))
            .join("")
    );
    let pub_key = priv_key.public_key(&Secp256k1::signing_only());
    println!(
        "Public key: {}",
        pub_key
            .serialize()
            .iter()
            .map(|&c| format!("{:02x}", c))
            .join("")
    );
    println!("Address: {}", pub_key.address().to_checksum_address())
}

#[test]
fn test_run() {
    create_wallet();
}

fn main() {
    create_wallet();
}
