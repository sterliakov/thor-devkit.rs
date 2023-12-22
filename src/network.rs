//! Module for interacting with node HTTP APIs.

use crate::rlp::{Bytes, Decodable};
use crate::utils::unhex;
use crate::U256;
use crate::{transactions::Transaction, Address};
use reqwest::{Client, Url};
use rustc_hex::ToHex;
use serde::Deserialize;
type AResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

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

/// Transaction metadata
#[serde_with::serde_as]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct TransactionMeta {
    /// Block identifier
    #[serde(rename = "blockID")]
    #[serde_as(as = "unhex::Hex")]
    pub block_id: [u8; 32],
    /// Block number (height)
    #[serde(rename = "blockNumber")]
    pub block_number: i32,
    /// Block unix timestamp
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: i32,
}

/// Transaction receipt
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Receipt {
    /// Amount of gas consumed by this transaction
    #[serde(rename = "gasUsed")]
    pub gas_used: i32,
    /// Address of account who paid used gas
    #[serde(rename = "gasPayer")]
    pub gas_payer: Address,
    /// Hex form of amount of paid energy
    #[serde(rename = "paid")]
    pub paid: U256,
    /// Hex form of amount of reward
    #[serde(rename = "reward")]
    pub reward: U256,
    /// true means the transaction was reverted
    #[serde(rename = "reverted")]
    pub reverted: bool,
    /// Outputs (if this transaction was a contract call)
    #[serde(rename = "outputs")]
    pub outputs: Vec<ReceiptOutput>,
    /// Receipt metadata
    #[serde(rename = "meta")]
    pub meta: ReceiptMeta,
}

/// Single output in the transaction receipt
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ReceiptOutput {
    /// Deployed contract address, if the corresponding clause is a contract deployment clause
    #[serde(rename = "contractAddress")]
    pub contract_address: Option<Address>,
    /// Emitted contract events
    #[serde(rename = "events")]
    pub events: Vec<Event>,
    /// Transfers executed during the contract call
    #[serde(rename = "transfers")]
    pub transfers: Vec<Transfer>,
}

/// Transaction receipt metadata
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ReceiptMeta {
    /// Block identifier (bytes32)
    #[serde(rename = "blockID")]
    #[serde_as(as = "unhex::Hex")]
    pub block_id: [u8; 32],
    /// Block number (height)
    #[serde(rename = "blockNumber")]
    pub block_number: i32,
    /// Block unix timestamp
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: i32,
    /// Transaction identifier
    #[serde(rename = "txID")]
    #[serde_as(as = "unhex::Hex")]
    pub tx_id: [u8; 32],
    /// Transaction origin (signer)
    #[serde(rename = "txOrigin")]
    pub tx_origin: Address,
}

/// Emitted contract event
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Event {
    /// The address of contract which produces the event
    #[serde(rename = "address")]
    pub address: Address,
    /// Event topics
    #[serde(rename = "topics")]
    #[serde_as(as = "Vec<unhex::Hex>")]
    pub topics: Vec<[u8; 32]>,
    /// Event data
    #[serde(rename = "data")]
    #[serde_as(as = "unhex::Hex")]
    pub data: Bytes,
}

/// Single transfer during the contract call
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Transfer {
    /// Address that sends tokens
    #[serde(rename = "sender")]
    pub sender: Address,
    /// Address that receives tokens
    #[serde(rename = "recipient")]
    pub recipient: Address,
    /// Amount of tokens
    #[serde(rename = "amount")]
    pub amount: U256,
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
        transaction_id: [u8; 32],
    ) -> AResult<Option<(Transaction, Option<TransactionMeta>)>> {
        //! Retrieve a [`Transaction`] from node by its ID.
        //!
        //! Returns [`None`] for nonexistent transactions.
        //!
        //! Meta can be [`None`] if a transaction was broadcasted, but
        //! not yet included into a block.
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

    pub async fn fetch_transaction_receipt(
        &self,
        transaction_id: [u8; 32],
    ) -> AResult<Option<Receipt>> {
        //! Retrieve a [`Transaction`] from node by its ID.
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
            let decoded: Receipt = serde_json::from_str(&response)?;
            Ok(Some(decoded))
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
