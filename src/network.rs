//! Module for interacting with node HTTP APIs.

use crate::rlp::{Bytes, Decodable};
use crate::transactions::Reserved;
use crate::utils::unhex;
use crate::U256;
use crate::{
    transactions::{Clause, Transaction},
    Address,
};
use reqwest::{Client, Url};
use rustc_hex::ToHex;
use serde::Deserialize;

/// Generic result of all asynchronous calls in this module.
pub type AResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// 256-byte binary sequence (usually a hash of something)
pub type Hash256 = [u8; 32];

/// A simple HTTP REST client for a VeChain node.
pub struct ThorNode {
    base_url: Url,
    #[allow(dead_code)]
    chain_tag: u8,
}

#[serde_with::serde_as]
#[derive(Deserialize)]
struct RawTxResponse {
    #[serde_as(as = "unhex::Hex")]
    raw: Bytes,
    meta: Option<TransactionMeta>,
}

/// Extended transaction data
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ExtendedTransaction {
    /// Identifier of the transaction
    #[serde_as(as = "unhex::Hex")]
    pub id: Hash256,
    /// The one who signed the transaction
    pub origin: Address,
    /// The delegator who paid the gas fee
    pub delegator: Option<Address>,
    /// Byte size of the transaction that is RLP encoded
    pub size: u32,
    /// Last byte of genesis block ID
    #[serde(rename = "chainTag")]
    pub chain_tag: u8,
    /// 8 bytes prefix of some block ID
    #[serde(rename = "blockRef")]
    #[serde_as(as = "unhex::HexNum<8, u64>")]
    pub block_ref: u64,
    /// Expiration relative to blockRef, in unit block
    pub expiration: u32,
    /// Transaction clauses
    pub clauses: Vec<Clause>,
    /// Coefficient used to calculate the final gas price
    #[serde(rename = "gasPriceCoef")]
    pub gas_price_coef: u8,
    /// Max amount of gas can be consumed to execute this transaction
    pub gas: u64,
    /// ID of the transaction on which the current transaction depends on. can be null.
    #[serde(rename = "dependsOn")]
    #[serde_as(as = "Option<unhex::HexNum<32, U256>>")]
    pub depends_on: Option<U256>,
    /// Transaction nonce
    #[serde_as(as = "unhex::HexNum<8, u64>")]
    pub nonce: u64,
}

impl ExtendedTransaction {
    pub fn as_transaction(self) -> Transaction {
        //! Convert to package-compatible [`Transaction`]
        let Self {
            chain_tag,
            block_ref,
            expiration,
            clauses,
            gas_price_coef,
            gas,
            depends_on,
            nonce,
            delegator,
            ..
        } = self;
        Transaction {
            chain_tag,
            block_ref,
            expiration,
            clauses,
            gas_price_coef,
            gas,
            depends_on,
            nonce,
            reserved: if delegator.is_some() {
                Some(Reserved::new_delegated())
            } else {
                None
            },
            signature: None,
        }
    }
}

#[serde_with::serde_as]
#[derive(Deserialize)]
struct ExtendedTransactionResponse {
    #[serde(flatten)]
    transaction: ExtendedTransaction,
    meta: Option<TransactionMeta>,
}

/// Transaction metadata
#[serde_with::serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct TransactionMeta {
    /// Block identifier
    #[serde(rename = "blockID")]
    #[serde_as(as = "unhex::Hex")]
    pub block_id: Hash256,
    /// Block number (height)
    #[serde(rename = "blockNumber")]
    pub block_number: u32,
    /// Block unix timestamp
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: u32,
}

/// Transaction receipt
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Receipt {
    /// Amount of gas consumed by this transaction
    #[serde(rename = "gasUsed")]
    pub gas_used: u32,
    /// Address of account who paid used gas
    #[serde(rename = "gasPayer")]
    pub gas_payer: Address,
    /// Hex form of amount of paid energy
    pub paid: U256,
    /// Hex form of amount of reward
    pub reward: U256,
    /// true means the transaction was reverted
    pub reverted: bool,
    /// Outputs (if this transaction was a contract call)
    pub outputs: Vec<ReceiptOutput>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
struct ReceiptResponse {
    #[serde(flatten)]
    body: Receipt,
    meta: ReceiptMeta,
}

/// Single output in the transaction receipt
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ReceiptOutput {
    /// Deployed contract address, if the corresponding clause is a contract deployment clause
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<Address>,
    /// Emitted contract events
    pub events: Vec<Event>,
    /// Transfers executed during the contract call
    pub transfers: Vec<Transfer>,
}

/// Transaction receipt metadata
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ReceiptMeta {
    /// Block identifier
    #[serde(rename = "blockID")]
    #[serde_as(as = "unhex::Hex")]
    pub block_id: Hash256,
    /// Block number (height)
    #[serde(rename = "blockNumber")]
    pub block_number: u32,
    /// Block unix timestamp
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: u32,
    /// Transaction identifier
    #[serde(rename = "txID")]
    #[serde_as(as = "unhex::Hex")]
    pub tx_id: Hash256,
    /// Transaction origin (signer)
    #[serde(rename = "txOrigin")]
    pub tx_origin: Address,
}

/// Emitted contract event
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Event {
    /// The address of contract which produces the event
    pub address: Address,
    /// Event topics
    #[serde_as(as = "Vec<unhex::Hex>")]
    pub topics: Vec<Hash256>,
    /// Event data
    #[serde_as(as = "unhex::Hex")]
    pub data: Bytes,
}

/// Single transfer during the contract call
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Transfer {
    /// Address that sends tokens
    pub sender: Address,
    /// Address that receives tokens
    pub recipient: Address,
    /// Amount of tokens
    pub amount: U256,
}

/// A blockchain block.
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct BlockInfo {
    /// Block number (height)
    pub number: u32,
    /// Block identifier
    #[serde_as(as = "unhex::Hex")]
    pub id: Hash256,
    /// RLP encoded block size in bytes
    pub size: u32,
    /// Parent block ID
    #[serde_as(as = "unhex::Hex")]
    #[serde(rename = "parentID")]
    pub parent_id: Hash256,
    /// Block unix timestamp
    pub timestamp: u32,
    /// Block gas limit (max allowed accumulative gas usage of transactions)
    #[serde(rename = "gasLimit")]
    pub gas_limit: u32,
    /// Address of account to receive block reward
    pub beneficiary: Address,
    /// Accumulative gas usage of transactions
    #[serde(rename = "gasUsed")]
    pub gas_used: u32,
    /// Sum of all ancestral blocks' score
    #[serde(rename = "totalScore")]
    pub total_score: u32,
    /// Root hash of transactions in the block
    #[serde_as(as = "unhex::Hex")]
    #[serde(rename = "txsRoot")]
    pub txs_root: Hash256,
    /// Supported txs features bitset
    #[serde(rename = "txsFeatures")]
    pub txs_features: u32,
    /// Root hash of accounts state
    #[serde_as(as = "unhex::Hex")]
    #[serde(rename = "stateRoot")]
    pub state_root: Hash256,
    /// Root hash of transaction receipts
    #[serde_as(as = "unhex::Hex")]
    #[serde(rename = "receiptsRoot")]
    pub receipts_root: Hash256,
    /// Is in trunk?
    #[serde(rename = "isTrunk")]
    pub is_trunk: bool,
    /// Is finalized?
    #[serde(rename = "isFinalized")]
    pub is_finalized: bool,
    /// Whether the block signer voted COM(Commit) in BFT
    pub com: bool,
    /// The one who signed this block
    pub signer: Address,
}

/// Transaction data included in the block extended details.
///
/// Combines [`ExtendedTransaction`] and [`Receipt`].
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct BlockTransaction {
    /// Transaction details
    #[serde(flatten)]
    pub transaction: ExtendedTransaction,
    /// Transaction receipt
    #[serde(flatten)]
    pub receipt: Receipt,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
struct BlockResponse {
    #[serde(flatten)]
    base: BlockInfo,
    #[serde_as(as = "Vec<unhex::Hex>")]
    transactions: Vec<Hash256>,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
struct BlockExtendedResponse {
    #[serde(flatten)]
    base: BlockInfo,
    transactions: Vec<BlockTransaction>,
}

/// Block reference: a way to identify the block on the chain.
#[derive(Clone, Debug)]
pub enum BlockReference {
    /// Latest: already approved by some node, but not finalized yet.
    Best,
    /// Finalized: block is frozen on chain.
    Finalized,
    /// Block ordinal number (1..)
    Number(u64),
    /// Block ID
    ID(Hash256),
}

impl BlockReference {
    fn as_query_param(&self) -> String {
        match self {
            BlockReference::Best => "best".to_string(),
            BlockReference::Finalized => "finalized".to_string(),
            BlockReference::Number(num) => format!("0x{:02x}", num),
            BlockReference::ID(id) => {
                let hex: String = id.to_hex();
                format!("0x{}", hex)
            }
        }
    }
}

impl ThorNode {
    /// Chain tag for mainnet
    pub const MAINNET_CHAIN_TAG: u8 = 0x4A;
    /// REST API URL for mainnet (one possible)
    pub const MAINNET_BASE_URL: &'static str = "https://mainnet.vecha.in/";
    /// Chain tag for testnet
    pub const TESTNET_CHAIN_TAG: u8 = 0x27;
    /// REST API URL for testnet (one possible)
    pub const TESTNET_BASE_URL: &'static str = "https://testnet.vecha.in/";

    pub fn mainnet() -> Self {
        //! Mainnet parameters
        Self {
            base_url: Self::MAINNET_BASE_URL.parse().unwrap(),
            chain_tag: Self::MAINNET_CHAIN_TAG,
        }
    }

    pub fn testnet() -> Self {
        //! Testnet parameters
        Self {
            base_url: Self::TESTNET_BASE_URL.parse().unwrap(),
            chain_tag: Self::TESTNET_CHAIN_TAG,
        }
    }

    pub async fn fetch_transaction(
        &self,
        transaction_id: Hash256,
    ) -> AResult<Option<(Transaction, Option<TransactionMeta>)>> {
        //! Retrieve a [`Transaction`] from node by its ID.
        //!
        //! Returns [`None`] for nonexistent transactions.
        //!
        //! Meta can be [`None`] if a transaction was broadcasted, but
        //! not yet included into a block.
        //!
        //! This method exists for interoperability with [`Transaction`]
        //! from other parts of library. You can get more info from node
        //! with [`ThorNode::fetch_extended_transaction`].
        let client = Client::new();
        let hex_id: String = transaction_id.to_hex();
        let path = format!("/transactions/0x{}", hex_id);
        let response = client
            .get(self.base_url.join(&path)?)
            .query(&[("raw", "true")])
            .send()
            .await?
            .text()
            .await?;
        if response.strip_suffix('\n').unwrap_or(&response) == "null" {
            Ok(None)
        } else {
            let decoded: RawTxResponse = serde_json::from_str(&response)?;
            let tx = Transaction::decode(&mut &decoded.raw[..])?;
            Ok(Some((tx, decoded.meta)))
        }
    }

    pub async fn fetch_extended_transaction(
        &self,
        transaction_id: Hash256,
    ) -> AResult<Option<(ExtendedTransaction, Option<TransactionMeta>)>> {
        //! Retrieve a [`Transaction`] from node by its ID.
        //!
        //! Returns [`None`] for nonexistent transactions.
        //!
        //! Meta can be [`None`] if a transaction was broadcasted, but
        //! not yet included into a block.
        //!
        //! This method returns more data than [`ThorNode::fetch_transaction`],
        //! but is not interoperable with [`Transaction`].
        let client = Client::new();
        let hex_id: String = transaction_id.to_hex();
        let path = format!("/transactions/0x{}", hex_id);
        let response = client
            .get(self.base_url.join(&path)?)
            .send()
            .await?
            .text()
            .await?;
        if response.strip_suffix('\n').unwrap_or(&response) == "null" {
            Ok(None)
        } else {
            let decoded: ExtendedTransactionResponse = serde_json::from_str(&response)?;
            Ok(Some((decoded.transaction, decoded.meta)))
        }
    }

    pub async fn fetch_transaction_receipt(
        &self,
        transaction_id: Hash256,
    ) -> AResult<Option<(Receipt, ReceiptMeta)>> {
        //! Retrieve a transaction receipt from node given a transaction ID.
        //!
        //! Returns [`None`] for nonexistent or not mined transactions.
        let client = Client::new();
        let hex_id: String = transaction_id.to_hex();
        let path = format!("/transactions/0x{}/receipt", hex_id);
        let response = client
            .get(self.base_url.join(&path)?)
            .send()
            .await?
            .text()
            .await?;
        if response.strip_suffix('\n').unwrap_or(&response) == "null" {
            Ok(None)
        } else {
            let decoded: ReceiptResponse = serde_json::from_str(&response)?;
            Ok(Some((decoded.body, decoded.meta)))
        }
    }

    pub async fn fetch_block(
        &self,
        block_ref: BlockReference,
    ) -> AResult<Option<(BlockInfo, Vec<Hash256>)>> {
        //! Retrieve a block from node by given identifier.
        //!
        //! Returns [`None`] for nonexistent blocks.
        let client = Client::new();
        let path = format!("/blocks/{}", block_ref.as_query_param());
        let response = client
            .get(self.base_url.join(&path)?)
            .send()
            .await?
            .text()
            .await?;
        if response.strip_suffix('\n').unwrap_or(&response) == "null" {
            Ok(None)
        } else {
            let decoded: BlockResponse = serde_json::from_str(&response)?;
            Ok(Some((decoded.base, decoded.transactions)))
        }
    }

    pub async fn fetch_block_expanded(
        &self,
        block_ref: BlockReference,
    ) -> AResult<Option<(BlockInfo, Vec<BlockTransaction>)>> {
        //! Retrieve a block from node by given identifier together with extended
        //! transaction details.
        //!
        //! Returns [`None`] for nonexistent blocks.
        let client = Client::new();
        let path = format!("/blocks/{}", block_ref.as_query_param());
        let response = client
            .get(self.base_url.join(&path)?)
            .query(&[("expanded", "true")])
            .send()
            .await?
            .text()
            .await?;
        if response.strip_suffix('\n').unwrap_or(&response) == "null" {
            Ok(None)
        } else {
            let decoded: BlockExtendedResponse = serde_json::from_str(&response)?;
            Ok(Some((decoded.base, decoded.transactions)))
        }
    }

    pub async fn broadcast_transaction(&self, transaction: &Transaction) -> AResult<()> {
        //! Broadcast a new [`Transaction`] to the node.
        let client = Client::new();
        client
            .post(self.base_url.join("/transactions/")?)
            .body(transaction.to_broadcastable_bytes()?)
            .send()
            .await?;
        Ok(())
    }
}
