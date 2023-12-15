//! VeChain-tailored Hierarchically deterministic nodes support
//!
//! `Reference <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>`

use std::str::FromStr;

use bip32::{
    ChainCode, ChildNumber, DerivationPath, Error as Bip32Error, ExtendedKey, ExtendedKeyAttrs,
    ExtendedPrivateKey, ExtendedPublicKey, Prefix, Result,
};
pub use bip39::{Language, Mnemonic};
use either::{Either, Left, Right};
use secp256k1::{PublicKey, SecretKey as PrivateKey};

/// Default HD derivation path for VeChain
pub const VET_EXTERNAL_PATH: &str = "m/44'/818'/0'/0";

// TODO: add zeroize
// TODO: wrap with custom, more human-friendly errors

/// HD Node wrapper
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HDNode(Either<ExtendedPrivateKey<PrivateKey>, ExtendedPublicKey<PublicKey>>);

impl HDNode {
    pub fn from_seed_vet<S: AsRef<[u8]>>(seed: S) -> Result<Self> {
        //! Create an HDNode from seed using default derivation path.
        Self::from_seed(seed, VET_EXTERNAL_PATH)
    }
    pub fn from_seed<S: AsRef<[u8]>>(seed: S, init_path: &str) -> Result<Self> {
        //! Create an HDNode using the seed and the given derivation path.
        let path = DerivationPath::from_str(init_path)?;
        ExtendedPrivateKey::derive_from_path(seed, &path).map(|k| Self(Left(k)))
    }

    pub fn from_mnemonic_vet(mnemonic: Mnemonic) -> Result<Self> {
        //! Create an HDNode from mnemonic using default derivation path.
        Self::from_mnemonic_with_password_vet(mnemonic, "")
    }
    pub fn from_mnemonic_with_password_vet(mnemonic: Mnemonic, password: &str) -> Result<Self> {
        //! Create an HDNode from mnemonic and password using default derivation path.
        Self::from_mnemonic_with_password(mnemonic, password, VET_EXTERNAL_PATH)
    }
    pub fn from_mnemonic(mnemonic: Mnemonic, init_path: &str) -> Result<Self> {
        //! Create an HDNode from mnemonic and the given derivation path.
        Self::from_mnemonic_with_password(mnemonic, "", init_path)
    }
    pub fn from_mnemonic_with_password(
        mnemonic: Mnemonic,
        password: &str,
        init_path: &str,
    ) -> Result<Self> {
        //! Create an HDNode from mnemonic, password and the given derivation path.
        let path = DerivationPath::from_str(init_path)?;
        ExtendedPrivateKey::derive_from_path(bip39::Seed::new(&mnemonic, password), &path)
            .map(|k| Self(Left(k)))
    }

    pub fn from_private_key_master<S: Into<[u8; 33]>, T: Into<ChainCode>>(
        key: S,
        chain_code: T,
    ) -> Result<Self> {
        //! Create an HDNode from private key bytes and chain code.
        let ext_key = ExtendedKey {
            prefix: Prefix::XPRV,
            attrs: ExtendedKeyAttrs {
                depth: 0,
                parent_fingerprint: [0; 4],
                child_number: ChildNumber(0u32),
                chain_code: chain_code.into(),
            },
            key_bytes: key.into(),
        };
        Self::from_extended_private_key(ext_key)
    }
    pub fn from_extended_private_key(ext_key: ExtendedKey) -> Result<Self> {
        //! Create an HDNode from extended private key structure.
        Ok(Self(Left(ext_key.try_into()?)))
    }

    pub fn from_public_key_master<S: Into<[u8; 33]>, T: Into<ChainCode>>(
        key: S,
        chain_code: T,
    ) -> Result<Self> {
        //! Create an HDNode from private key bytes and chain code.
        //!
        //! Beware that this node cannot be used to derive new private keys.
        let ext_key = ExtendedKey {
            prefix: Prefix::XPUB,
            attrs: ExtendedKeyAttrs {
                depth: 0,
                parent_fingerprint: [0; 4],
                child_number: ChildNumber(0u32),
                chain_code: chain_code.into(),
            },
            key_bytes: key.into(),
        };
        Self::from_extended_public_key(ext_key)
    }
    pub fn from_extended_public_key(ext_key: ExtendedKey) -> Result<Self> {
        //! Create an HDNode from extended public key structure.
        //!
        //! Beware that this node cannot be used to derive new private keys.
        Ok(Self(Right(ext_key.try_into()?)))
    }

    pub fn derive(&self, index: u32) -> Result<Self> {
        //! Derive a child given an index.
        let child = match &self.0 {
            Left(privkey) => Self(Left(privkey.derive_child(ChildNumber(index))?)),
            Right(pubkey) => Self(Right(pubkey.derive_child(ChildNumber(index))?)),
        };
        Ok(child)
    }

    pub fn public_key(&self) -> ExtendedPublicKey<PublicKey> {
        //! Get underlying public key.
        match &self.0 {
            Left(privkey) => privkey.public_key(),
            Right(pubkey) => pubkey.clone(),
        }
    }
    pub fn private_key(&self) -> Result<ExtendedPrivateKey<PrivateKey>> {
        //! Get underlying private key.
        match &self.0 {
            Left(privkey) => Ok(privkey.clone()),
            Right(_) => Err(Bip32Error::Crypto),
        }
    }
    pub fn chain_code(&self) -> ChainCode {
        //! Get underlying chain code.
        match &self.0 {
            Left(privkey) => privkey.attrs().chain_code,
            Right(pubkey) => pubkey.attrs().chain_code,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::address::decode_hex;

    #[test]
    fn test_from_seed() {
        //! Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        let seed = decode_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let node = HDNode::from_seed(seed.clone(), "m").unwrap();
        assert_eq!(node.public_key().to_string(Prefix::XPUB), "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
        assert_eq!(node.private_key().unwrap().to_string(Prefix::XPRV).as_str(), "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");

        let node = HDNode::from_seed(seed.clone(), "m/0").unwrap();
        assert_eq!(node.public_key().to_string(Prefix::XPUB), "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
        assert_eq!(node.private_key().unwrap().to_string(Prefix::XPRV).as_str(), "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");

        let node = HDNode::from_seed(seed.clone(), "m/0/2147483647'").unwrap();
        assert_eq!(node.public_key().to_string(Prefix::XPUB), "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
        assert_eq!(node.private_key().unwrap().to_string(Prefix::XPRV).as_str(), "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");
    }

    #[test]
    fn test_from_mnemonic_vet() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "ignore empty bird silly journey junior ripple have guard waste between tenant",
            bip39::Language::English,
        )
        .unwrap();
        let private = "e4a2687ec443f4d23b6ba9e7d904a31acdda90032b34aa0e642e6dd3fd36f682";
        let public = "04dc40b4324626eb393dbf77b6930e915dcca6297b42508adb743674a8ad5c69a046010f801a62cb945a6cb137a050cefaba0572429fc4afc57df825bfca2f219a";
        let chain_code = "105da5578eb3228655a8abe70bf4c317e525c7f7bb333634f5b7d1f70e111a33";
        let node = HDNode::from_mnemonic_vet(mnemonic).unwrap();
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
    }

    #[test]
    fn test_derive() {
        //! Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        let seed = decode_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        // Not hardened
        let node = HDNode::from_seed(seed.clone(), "m").unwrap();
        let node_exp = HDNode::from_seed(seed.clone(), "m/0").unwrap();
        assert_eq!(node.derive(0).unwrap(), node_exp,);

        // Hardened
        let node = HDNode::from_seed(seed.clone(), "m/0").unwrap();
        let node_exp = HDNode::from_seed(seed.clone(), "m/0/2147483647'").unwrap();
        let derived = node.derive(2147483647 + (1 << 31)).unwrap();
        assert_eq!(derived, node_exp,);
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
        let pk = ExtendedKey::from_str(ext_pk).unwrap();
        let node = HDNode::from_extended_private_key(pk.clone()).unwrap();
        assert_eq!(
            node.private_key().unwrap().to_string(Prefix::XPRV).as_str(),
            ext_pk
        );
        assert_eq!(
            node.public_key().to_string(Prefix::XPUB).as_str(),
            "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
        );

        let other_node =
            HDNode::from_private_key_master(pk.key_bytes, pk.attrs.chain_code).unwrap();
        assert_eq!(node, other_node);

        let derived_ext_pk = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";
        let derived_pk = ExtendedKey::from_str(derived_ext_pk).unwrap();
        let derived_exp = HDNode::from_extended_private_key(derived_pk).unwrap();
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
        let pk = ExtendedKey::from_str(ext_pub).unwrap();
        let node = HDNode::from_extended_public_key(pk.clone()).unwrap();
        assert_eq!(node.private_key().unwrap_err(), Bip32Error::Crypto);
        assert_eq!(node.public_key().to_string(Prefix::XPUB).as_str(), ext_pub);

        let other_node = HDNode::from_public_key_master(pk.key_bytes, pk.attrs.chain_code).unwrap();
        assert_eq!(node, other_node);

        // Cannot derive public->public hardened
        let derived_failed = node.derive(0 + (1 << 31));
        assert_eq!(derived_failed.unwrap_err(), Bip32Error::ChildNumber);
    }

    #[test]
    fn test_from_public_key_can_derive() {
        let ext_pub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        let pk = ExtendedKey::from_str(ext_pub).unwrap();
        let node = HDNode::from_extended_public_key(pk).unwrap();
        assert_eq!(node.private_key().unwrap_err(), Bip32Error::Crypto);
        assert_eq!(node.public_key().to_string(Prefix::XPUB).as_str(), ext_pub);

        // Cannot derive public->public hardened
        let derived = node.derive(2).unwrap();
        assert_eq!(derived.private_key().unwrap_err(), Bip32Error::Crypto);
        assert_eq!(
            derived.public_key().to_string(Prefix::XPUB).as_str(),
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        );
    }
}
