//! VeChain-tailored hierarchically deterministic nodes support
//!
//! [In-deep explanation](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//!
//! This module glues together several important components involved in key derivation
//! from different sources. You can construct an [`HDNode`] in multiple ways, allowing,
//! for example, generating a private key from mnemonic or generating a random key.

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
///
/// To construct a wallet, use the [`HDNode::build`] method. It exposes access to the builder
/// that supports multiple construction methods and validates the arguments.
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
        //! Get underlying extended public key.
        match &self.0 {
            Full(privkey) => privkey.public_key(),
            Restricted(pubkey) => pubkey.clone(),
        }
    }
    pub fn private_key(&self) -> Result<ExtendedPrivateKey<PrivateKey>, HDNodeError> {
        //! Get underlying extended private key.
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
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        //! Get underlying chain code.
        match &self.0 {
            Full(privkey) => privkey.attrs().parent_fingerprint,
            Restricted(pubkey) => pubkey.attrs().parent_fingerprint,
        }
    }
    pub fn child_number(&self) -> ChildNumber {
        //! Get underlying chain code.
        match &self.0 {
            Full(privkey) => privkey.attrs().child_number,
            Restricted(pubkey) => pubkey.attrs().child_number,
        }
    }
    pub fn depth(&self) -> u8 {
        //! Get underlying chain code.
        match &self.0 {
            Full(privkey) => privkey.attrs().depth,
            Restricted(pubkey) => pubkey.attrs().depth,
        }
    }
    pub fn address(&self) -> crate::address::Address {
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

#[cfg(not(tarpaulin_include))]
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

#[cfg(not(tarpaulin_include))]
impl From<bip32::Error> for HDNodeError {
    fn from(err: bip32::Error) -> HDNodeError {
        match err {
            bip32::Error::Crypto => HDNodeError::Crypto,
            bip32::Error::Decode => HDNodeError::Parse,
            bip32::Error::ChildNumber => HDNodeError::WrongChildNumber,
            err => HDNodeError::Custom(format!("{err:?}")),
        }
    }
}

/// Builder for HDNode: use this to construct a node from different sources.
///
/// The following sources are supported:
/// - Binary seed. 64 bytes of raw entropy to use for key generation.
/// - [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonic
///   with optional password. This method is compatible with derivation in Sync2 wallet.
/// - Master private key bytes and chain code
/// - Extended private key
/// - Master public key bytes and chain code
/// - Extended public key
///
/// First two methods accept a derivation path to use (defaults to VeChain path).
///
/// For example, here's what you could do:
///
/// ```rust
/// use thor_devkit::hdnode::{Mnemonic, Language, HDNode};
/// use rand::RngCore;
///
/// let mnemonic = Mnemonic::from_phrase(
///     "ignore empty bird silly journey junior ripple have guard waste between tenant",
///     Language::English,
/// )
/// .expect("Should be constructible");
/// let wallet = HDNode::build().mnemonic(mnemonic).build().expect("Must be buildable");
/// // OR
/// let mut entropy = [0u8; 64];
/// rand::rng().fill_bytes(&mut entropy);
/// let other_wallet = HDNode::build().seed(entropy).build().expect("Must be buildable");
/// ```
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
    pub const fn seed(mut self, seed: [u8; 64]) -> Self {
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

    pub fn master_private_key_bytes<T: Into<ChainCode>>(
        mut self,
        key: [u8; 33],
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
            key_bytes: key,
        });
        self
    }
    pub fn private_key(mut self, ext_key: ExtendedKey) -> Self {
        //! Create an HDNode from extended private key structure.
        self.ext_privkey = Some(ext_key);
        self
    }

    pub fn master_public_key_bytes<T: Into<ChainCode>>(
        mut self,
        key: [u8; 33],
        chain_code: T,
    ) -> Self {
        //! Create an HDNode from private key bytes and chain code.
        //!
        //! <div class="warning">
        //! Beware that this node cannot be used to derive new private keys.
        //! </div>
        self.ext_pubkey = Some(ExtendedKey {
            prefix: Prefix::XPUB,
            attrs: ExtendedKeyAttrs {
                depth: 0,
                parent_fingerprint: [0; 4],
                child_number: ChildNumber(0u32),
                chain_code: chain_code.into(),
            },
            key_bytes: key,
        });
        self
    }
    pub fn public_key(mut self, ext_key: ExtendedKey) -> Self {
        //! Create an HDNode from extended public key structure.
        //!
        //! <div class="warning">
        //! Beware that this node cannot be used to derive new private keys.
        //! </div>
        self.ext_pubkey = Some(ext_key);
        self
    }

    pub fn build(self) -> Result<HDNode, HDNodeError> {
        //! Create an HDNode from given arguments.
        match (self.seed, self.mnemonic, self.ext_privkey, self.ext_pubkey) {
            (Some(seed), None, None, None) => {
                let path = self.path.unwrap_or_else(|| {
                    VET_EXTERNAL_PATH
                        .parse()
                        .expect("hardcoded path must be valid")
                });
                Ok(ExtendedPrivateKey::derive_from_path(seed, &path).map(|k| HDNode(Full(k)))?)
            }
            (None, Some(mnemonic), None, None) => {
                let path = self.path.unwrap_or_else(|| {
                    VET_EXTERNAL_PATH
                        .parse()
                        .expect("hardcoded path must be valid")
                });
                Ok(ExtendedPrivateKey::derive_from_path(
                    bip39::Seed::new(&mnemonic, self.password.unwrap_or("")),
                    &path,
                )
                .map(|k| HDNode(Full(k)))?)
            }
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
