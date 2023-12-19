//! VeChain-tailored Hierarchically deterministic nodes support
//!
//! `Reference <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>`

use bip32::{
    ChainCode, ChildNumber, DerivationPath, ExtendedKey, ExtendedKeyAttrs, ExtendedPrivateKey,
    ExtendedPublicKey, Prefix,
};
pub use bip39::{Language, Mnemonic};
use secp256k1::{PublicKey, SecretKey as PrivateKey};

/// Default HD derivation path for VeChain
pub const VET_EXTERNAL_PATH: &str = "m/44'/818'/0'/0";

// TODO: add zeroize?

#[derive(Clone, Debug, Eq, PartialEq)]
enum HDNodeVariant {
    Full(ExtendedPrivateKey<PrivateKey>),
    Restricted(ExtendedPublicKey<PublicKey>),
}
use HDNodeVariant::{Full, Restricted};

/// Hierarchically deterministic node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HDNode(HDNodeVariant);

impl HDNode {
    pub fn build<'a>() -> HDNodeBuilder<'a> {
        //! Build an HDNode from various parameters
        HDNodeBuilder::default()
    }

    pub fn derive(&self, index: u32) -> Result<Self, HDNodeError> {
        //! Derive a child given an index.
        let child = match &self.0 {
            Full(privkey) => Self(Full(privkey.derive_child(ChildNumber(index))?)),
            Restricted(pubkey) => Self(Restricted(pubkey.derive_child(ChildNumber(index))?)),
        };
        Ok(child)
    }

    pub fn public_key(&self) -> ExtendedPublicKey<PublicKey> {
        //! Get underlying public key.
        match &self.0 {
            Full(privkey) => privkey.public_key(),
            Restricted(pubkey) => pubkey.clone(),
        }
    }
    pub fn private_key(&self) -> Result<ExtendedPrivateKey<PrivateKey>, HDNodeError> {
        //! Get underlying private key.
        match &self.0 {
            Full(privkey) => Ok(privkey.clone()),
            Restricted(_) => Err(HDNodeError::Crypto),
        }
    }
    pub fn chain_code(&self) -> ChainCode {
        //! Get underlying chain code.
        match &self.0 {
            Full(privkey) => privkey.attrs().chain_code,
            Restricted(pubkey) => pubkey.attrs().chain_code,
        }
    }
    pub fn address(self) -> crate::address::Address {
        //! Get the address of current node.
        use crate::address::AddressConvertible;

        match &self.0 {
            Full(privkey) => privkey.public_key().public_key().address(),
            Restricted(pubkey) => pubkey.public_key().address(),
        }
    }
}

/// Errors related to HDNode construction and operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HDNodeError {
    /// Failure of a cryptographic operation.
    Crypto,
    /// Failure of some parsing operation (e.g. wrong bytes length)
    Parse,
    /// Incorrect child number (above 2u32.pow(31) for derivation from public key)
    WrongChildNumber,
    /// Incompatible parameters
    Unbuildable(String),
    /// Other error with message
    Custom(String),
}

impl std::fmt::Display for HDNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto => f.write_str("cryptography error"),
            Self::Parse => f.write_str("decoding error"),
            Self::WrongChildNumber => {
                f.write_str("cannot derive hardened children from public key")
            }
            Self::Unbuildable(msg) => {
                f.write_str("cannot build HDNode:")?;
                f.write_str(msg)
            }
            Self::Custom(msg) => f.write_str(msg),
        }
    }
}
impl std::error::Error for HDNodeError {}

impl From<bip32::Error> for HDNodeError {
    fn from(err: bip32::Error) -> HDNodeError {
        match err {
            bip32::Error::Crypto => HDNodeError::Crypto,
            bip32::Error::Decode => HDNodeError::Parse,
            bip32::Error::ChildNumber => HDNodeError::WrongChildNumber,
            err => HDNodeError::Custom(format!("{:?}", err)),
        }
    }
}

/// Builder for HDNode: use this to construct a node from different sources.
#[derive(Clone, Default)]
pub struct HDNodeBuilder<'a> {
    path: Option<DerivationPath>,
    seed: Option<[u8; 64]>,
    mnemonic: Option<Mnemonic>,
    password: Option<&'a str>,
    ext_privkey: Option<ExtendedKey>,
    ext_pubkey: Option<ExtendedKey>,
}

impl<'a> HDNodeBuilder<'a> {
    pub fn path(mut self, path: DerivationPath) -> Self {
        //! Set a derivation path to use.
        //!
        //! If not called, defaults to `VET_EXTERNAL_PATH`.
        self.path = Some(path);
        self
    }
    pub fn seed(mut self, seed: [u8; 64]) -> Self {
        //! Set a seed to use.
        self.seed = Some(seed);
        self
    }

    pub fn mnemonic(mut self, mnemonic: Mnemonic) -> Self {
        //! Set a mnemonic to use. You may optionally provide a password as well.
        //!
        //! Derivation from mnemonic is compatible with Sync2 wallet (with empty password).
        self.mnemonic = Some(mnemonic);
        self
    }
    pub fn mnemonic_with_password(mut self, mnemonic: Mnemonic, password: &'a str) -> Self {
        //! Set a password for the mnemonic to use.
        //!
        //! Replaces previous mnemonic, if any.
        self.mnemonic = Some(mnemonic);
        self.password = Some(password);
        self
    }

    pub fn master_private_key_bytes<S: Into<[u8; 33]>, T: Into<ChainCode>>(
        mut self,
        key: S,
        chain_code: T,
    ) -> Self {
        //! Create an HDNode from private key bytes and chain code.
        self.ext_privkey = Some(ExtendedKey {
            prefix: Prefix::XPRV,
            attrs: ExtendedKeyAttrs {
                depth: 0,
                parent_fingerprint: [0; 4],
                child_number: ChildNumber(0u32),
                chain_code: chain_code.into(),
            },
            key_bytes: key.into(),
        });
        self
    }
    pub fn private_key(mut self, ext_key: ExtendedKey) -> Self {
        //! Create an HDNode from extended private key structure.
        self.ext_privkey = Some(ext_key);
        self
    }

    pub fn master_public_key_bytes<S: Into<[u8; 33]>, T: Into<ChainCode>>(
        mut self,
        key: S,
        chain_code: T,
    ) -> Self {
        //! Create an HDNode from private key bytes and chain code.
        //!
        //! Beware that this node cannot be used to derive new private keys.
        self.ext_pubkey = Some(ExtendedKey {
            prefix: Prefix::XPUB,
            attrs: ExtendedKeyAttrs {
                depth: 0,
                parent_fingerprint: [0; 4],
                child_number: ChildNumber(0u32),
                chain_code: chain_code.into(),
            },
            key_bytes: key.into(),
        });
        self
    }
    pub fn public_key(mut self, ext_key: ExtendedKey) -> Self {
        //! Create an HDNode from extended public key structure.
        //!
        //! Beware that this node cannot be used to derive new private keys.
        self.ext_pubkey = Some(ext_key);
        self
    }

    pub fn build(self) -> Result<HDNode, HDNodeError> {
        //! Create an HDNode from given arguments.
        let path = self.path.unwrap_or_else(|| {
            VET_EXTERNAL_PATH
                .parse()
                .expect("hardcoded path must be valid")
        });
        match (self.seed, self.mnemonic, self.ext_privkey, self.ext_pubkey) {
            (Some(seed), None, None, None) => {
                Ok(ExtendedPrivateKey::derive_from_path(seed, &path).map(|k| HDNode(Full(k)))?)
            }
            (None, Some(mnemonic), None, None) => Ok(ExtendedPrivateKey::derive_from_path(
                bip39::Seed::new(&mnemonic, self.password.unwrap_or("")),
                &path,
            )
            .map(|k| HDNode(Full(k)))?),
            (None, None, Some(ext_key), None) => Ok(HDNode(Full(ext_key.try_into()?))),
            (None, None, None, Some(ext_key)) => Ok(HDNode(Restricted(ext_key.try_into()?))),
            (None, None, None, None) => Err(HDNodeError::Unbuildable(
                "no parameters provided".to_string(),
            )),
            _ => Err(HDNodeError::Unbuildable(
                "incompatible parameters".to_string(),
            )),
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
        let mnemonic = bip39::Mnemonic::from_phrase(
            "ignore empty bird silly journey junior ripple have guard waste between tenant",
            bip39::Language::English,
        )
        .unwrap();
        let private = "e4a2687ec443f4d23b6ba9e7d904a31acdda90032b34aa0e642e6dd3fd36f682";
        let public = "04dc40b4324626eb393dbf77b6930e915dcca6297b42508adb743674a8ad5c69a046010f801a62cb945a6cb137a050cefaba0572429fc4afc57df825bfca2f219a";
        let chain_code = "105da5578eb3228655a8abe70bf4c317e525c7f7bb333634f5b7d1f70e111a33";
        let node = HDNode::build().mnemonic(mnemonic).build().unwrap();
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
        })
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
}
