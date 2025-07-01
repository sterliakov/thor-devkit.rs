use thor_devkit::rlp::Encodable;
use thor_devkit::{Address, AddressConvertible, PublicKey};

#[test]
fn test_upubkey_to_address() {
    let pubkey: PublicKey = (
        "04b90e9bb2617387eba4502c730de65a33878ef384a46f1096d86f2da19043304afa67d0ad09cf2bea0c6f2d1767a9e62a7a7ecc41facf18f2fa505d92243a658f"
    ).parse().unwrap();
    let ref_addr: Address = "d989829d88b0ed1b06edf5c50174ecfa64f14a64".parse().unwrap();
    assert_eq!(pubkey.address(), ref_addr);
}

#[test]
fn test_pubkey_to_address() {
    let pubkey: PublicKey = "03c1573f1528638ae14cbe04a74e6583c5562d59214223762c1a11121e24619cbc"
        .parse()
        .unwrap();
    let ref_addr: Address = "Af3CD5c36B97E9c28c263dC4639c6d7d53303A13".parse().unwrap();
    assert_eq!(pubkey.address(), ref_addr);
}

#[test]
fn test_can_create_from_raw() {
    let _ = Address::from([0; 20]);
}

#[test]
fn test_to_checksum_address() {
    let addresses = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        "0x00220a0cf47C7B9Be7a2e6ba89f429762e7B9adB",
    ];

    addresses.iter().for_each(|&addr| {
        assert_eq!(addr, addr.parse::<Address>().unwrap().to_checksum_address());
    });
    addresses.iter().for_each(|&addr| {
        assert_eq!(
            addr,
            addr.to_lowercase()
                .parse::<Address>()
                .unwrap()
                .to_checksum_address()
        );
    });
}

#[test]
fn test_encode() {
    let address: Address = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        .parse()
        .unwrap();
    let mut buf = vec![];
    address.encode(&mut buf);
    let expected = vec![
        0x94, 0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66, 0x94,
        0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed,
    ];
    assert!(buf == expected, "Encoding mismatch")
}

#[test]
fn test_encode_leading_zeros() {
    let address: Address = "0x00220a0cf47C7B9Be7a2e6ba89f429762e7B9adB"
        .parse()
        .unwrap();
    let mut buf = vec![];
    address.encode(&mut buf);
    let expected = vec![
        0x94, 0x00, 0x22, 0x0a, 0x0c, 0xf4, 0x7c, 0x7b, 0x9b, 0xe7, 0xa2, 0xe6, 0xba, 0x89, 0xf4,
        0x29, 0x76, 0x2e, 0x7b, 0x9a, 0xdb,
    ];
    assert!(buf == expected, "Encoding mismatch")
}
