use bip32::{ExtendedKey, ExtendedKeyAttrs, Prefix};
use bip39::{Language::English, Mnemonic};
use thor_devkit::decode_hex;
use thor_devkit::hdnode::*;

#[test]
fn test_from_seed() {
    //! Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    let seed = decode_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
    let node = HDNode::build()
        .seed(seed.clone().try_into().unwrap())
        .path("m".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(node.public_key().to_string(Prefix::XPUB), "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
    assert_eq!(node.private_key().unwrap().to_string(Prefix::XPRV).as_str(), "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");

    let node = HDNode::build()
        .seed(seed.clone().try_into().unwrap())
        .path("m/0".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(node.public_key().to_string(Prefix::XPUB), "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
    assert_eq!(node.private_key().unwrap().to_string(Prefix::XPRV).as_str(), "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");

    let node = HDNode::build()
        .seed(seed.clone().try_into().unwrap())
        .path("m/0/2147483647'".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(node.public_key().to_string(Prefix::XPUB), "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
    assert_eq!(node.private_key().unwrap().to_string(Prefix::XPRV).as_str(), "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");
}

#[test]
fn test_from_mnemonic_vet() {
    let mnemonic = Mnemonic::from_phrase(
        "ignore empty bird silly journey junior ripple have guard waste between tenant",
        English,
    )
    .unwrap();
    let private = "e4a2687ec443f4d23b6ba9e7d904a31acdda90032b34aa0e642e6dd3fd36f682";
    let public = "04dc40b4324626eb393dbf77b6930e915dcca6297b42508adb743674a8ad5c69a046010f801a62cb945a6cb137a050cefaba0572429fc4afc57df825bfca2f219a";
    let chain_code = "105da5578eb3228655a8abe70bf4c317e525c7f7bb333634f5b7d1f70e111a33";
    let node = HDNode::build().mnemonic(mnemonic.clone()).build().unwrap();
    assert_eq!(
        node.private_key()
            .unwrap()
            .private_key()
            .display_secret()
            .to_string(),
        private,
        "Private key differs"
    );
    assert_eq!(
        node.public_key()
            .public_key()
            .serialize_uncompressed()
            .to_vec(),
        decode_hex(public).unwrap(),
        "Public key differs"
    );
    assert_eq!(
        node.chain_code().to_vec(),
        decode_hex(chain_code).unwrap(),
        "Chain code differs"
    );
    let same_node = HDNode::build()
        .mnemonic_with_password(mnemonic, "")
        .build()
        .unwrap();
    assert_eq!(node, same_node);

    let addresses = vec![
        "0x339Fb3C438606519E2C75bbf531fb43a0F449A70",
        "0x5677099D06Bc72f9da1113aFA5e022feEc424c8E",
        "0x86231b5CDCBfE751B9DdCD4Bd981fC0A48afe921",
        "0xd6f184944335f26Ea59dbB603E38e2d434220fcD",
        "0x2AC1a0AeCd5C80Fb5524348130ab7cf92670470A",
    ];
    addresses.into_iter().enumerate().for_each(|(i, addr)| {
        assert_eq!(
            node.derive(i as u32)
                .unwrap()
                .address()
                .to_checksum_address(),
            addr
        );
    });

    let paired_public_node = HDNode::build()
        .public_key(ExtendedKey {
            prefix: Prefix::XPUB,
            attrs: ExtendedKeyAttrs {
                depth: node.depth(),
                parent_fingerprint: node.parent_fingerprint(),
                child_number: node.child_number(),
                chain_code: node.chain_code(),
            },
            key_bytes: node.public_key().to_bytes(),
        })
        .build()
        .expect("Must be buildable");
    assert_eq!(
        paired_public_node.private_key().unwrap_err(),
        HDNodeError::Crypto
    );
    assert_eq!(paired_public_node.public_key(), node.public_key());
    assert_eq!(paired_public_node.chain_code(), node.chain_code());
    assert_eq!(paired_public_node.depth(), node.depth());
    assert_eq!(
        paired_public_node.parent_fingerprint(),
        node.parent_fingerprint()
    );
    assert_eq!(paired_public_node.child_number(), node.child_number());
    assert_eq!(paired_public_node.address(), node.address());
}

#[test]
fn test_derive() {
    //! Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    let seed = decode_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
    // Not hardened
    let node = HDNode::build()
        .seed(seed.clone().try_into().unwrap())
        .path("m".parse().unwrap())
        .build()
        .unwrap();
    let node_exp = HDNode::build()
        .seed(seed.clone().try_into().unwrap())
        .path("m/0".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(node.derive(0).unwrap(), node_exp);

    // Hardened
    let node = HDNode::build()
        .seed(seed.clone().try_into().unwrap())
        .path("m/0".parse().unwrap())
        .build()
        .unwrap();
    let node_exp = HDNode::build()
        .seed(seed.clone().try_into().unwrap())
        .path("m/0/2147483647'".parse().unwrap())
        .build()
        .unwrap();
    let derived = node.derive(2147483647 + (1 << 31)).unwrap();
    assert_eq!(derived, node_exp);
    assert_eq!(
        derived.private_key().unwrap().to_string(Prefix::XPRV).as_str(),
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
    );
    assert_eq!(
        derived.public_key().to_string(Prefix::XPUB).as_str(),
        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
    );
}

#[test]
fn test_from_private_key() {
    let ext_pk = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
    let pk: ExtendedKey = ext_pk.parse().unwrap();
    let node = HDNode::build().private_key(pk.clone()).build().unwrap();
    assert_eq!(
        node.private_key().unwrap().to_string(Prefix::XPRV).as_str(),
        ext_pk
    );
    assert_eq!(
        node.public_key().to_string(Prefix::XPUB).as_str(),
        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
    );

    let other_node = HDNode::build()
        .master_private_key_bytes(pk.key_bytes, pk.attrs.chain_code)
        .build()
        .unwrap();
    assert_eq!(node, other_node);

    let derived_ext_pk = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";
    let derived_pk = derived_ext_pk.parse().unwrap();
    let derived_exp = HDNode::build().private_key(derived_pk).build().unwrap();
    let derived = node.derive(0 + (1 << 31)).unwrap();
    assert_eq!(
        derived
            .private_key()
            .unwrap()
            .to_string(Prefix::XPRV)
            .as_str(),
        derived_ext_pk
    );
    assert_eq!(
        derived.public_key().to_string(Prefix::XPUB).as_str(),
        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
    );
    assert_eq!(derived, derived_exp);
}

#[test]
fn test_from_public_key_cant_derive_hardened() {
    let ext_pub = "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa";
    let pk: ExtendedKey = ext_pub.parse().unwrap();
    let node = HDNode::build().public_key(pk.clone()).build().unwrap();
    assert_eq!(node.private_key().unwrap_err(), HDNodeError::Crypto);
    assert_eq!(node.public_key().to_string(Prefix::XPUB).as_str(), ext_pub);

    let other_node = HDNode::build()
        .master_public_key_bytes(pk.key_bytes, pk.attrs.chain_code)
        .build()
        .unwrap();
    assert_eq!(node, other_node);

    // Cannot derive public->public hardened
    let derived_failed = node.derive(0 + (1 << 31));
    assert_eq!(derived_failed.unwrap_err(), HDNodeError::WrongChildNumber);
}

#[test]
fn test_from_public_key_can_derive() {
    let ext_pub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    let pk = ext_pub.parse().unwrap();
    let node = HDNode::build().public_key(pk).build().unwrap();
    assert_eq!(node.private_key().unwrap_err(), HDNodeError::Crypto);
    assert_eq!(node.public_key().to_string(Prefix::XPUB).as_str(), ext_pub);

    // Cannot derive public->public hardened
    let derived = node.derive(2).unwrap();
    assert_eq!(derived.private_key().unwrap_err(), HDNodeError::Crypto);
    assert_eq!(
        derived.public_key().to_string(Prefix::XPUB).as_str(),
        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
    );
}

#[test]
fn test_build() {
    let mnemonic = Mnemonic::from_phrase(
        "ignore empty bird silly journey junior ripple have guard waste between tenant",
        English,
    )
    .unwrap();

    assert_eq!(
        HDNode::build().build().expect_err("Must fail"),
        HDNodeError::Unbuildable("no parameters provided".to_string())
    );
    assert_eq!(
        HDNode::build()
            .seed([0; 64])
            .master_private_key_bytes([0; 33], [0; 32])
            .build()
            .expect_err("Must fail"),
        HDNodeError::Unbuildable("incompatible parameters".to_string())
    );
    HDNode::build()
        .seed([0; 64])
        .build()
        .expect("Must be buildable");
    HDNode::build()
        .path("m/0/12'".parse().unwrap())
        .seed([0; 64])
        .build()
        .expect("Must be buildable");
    HDNode::build()
        .mnemonic(mnemonic.clone())
        .build()
        .expect("Must be buildable");
    HDNode::build()
        .path("m/0".parse().unwrap())
        .mnemonic(mnemonic.clone())
        .build()
        .expect("Must be buildable");
    HDNode::build()
        .master_private_key_bytes(
            decode_hex("00e4a2687ec443f4d23b6ba9e7d904a31acdda90032b34aa0e642e6dd3fd36f682")
                .unwrap()
                .try_into()
                .unwrap(),
            [0; 32],
        )
        .build()
        .expect("Must be buildable");
    HDNode::build()
        .master_public_key_bytes(
            decode_hex("035A784662A4A20A65BF6AAB9AE98A6C068A81C52E4B032C0FB5400C706CFCCC56")
                .unwrap()
                .try_into()
                .unwrap(),
            [0; 32],
        )
        .build()
        .expect("Must be buildable");
}
