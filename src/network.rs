//! Module for interacting with node HTTP APIs.

use crate::rlp::{Bytes, Decodable};
use crate::transactions::Reserved;
use crate::transactions::{Clause, Transaction};
use crate::utils::unhex;
use crate::{Address, U256};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

/// Generic result of all asynchronous calls in this module.
pub type AResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Validation errors (not related to HTTP failures)
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationError {
    /// Account storage keys start from one, there's no key 0.
    ZeroStorageKey,
    /// Transaction broadcast failed
    BroadcastFailed(String),
    /// Unexpected failure
    Unknown(String),
}

impl std::error::Error for ValidationError {}
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroStorageKey => f.write_str("Account storage key cannot be zero"),
            Self::BroadcastFailed(text) => {
                f.write_str("Failed to broadcast: ")?;
                f.write_str(text.strip_suffix('\n').unwrap_or(text))
            }
            Self::Unknown(text) => {
                f.write_str("Unknown error: ")?;
                f.write_str(text.strip_suffix('\n').unwrap_or(text))
            }
        }
    }
}

/// A simple HTTP REST client for a VeChain node.
#[derive(Clone, Debug)]
pub struct ThorNode {
    /// API base url
    pub base_url: Url,
    /// Chain tag used for this network.
    pub chain_tag: u8,
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtendedTransaction {
    /// Identifier of the transaction
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    pub id: U256,
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionMeta {
    /// Block identifier
    #[serde(rename = "blockID")]
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    pub block_id: U256,
    /// Block number (height)
    #[serde(rename = "blockNumber")]
    pub block_number: u32,
    /// Block unix timestamp
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: u32,
}

/// Transaction receipt
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReceiptMeta {
    /// Block identifier
    #[serde(rename = "blockID")]
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    pub block_id: U256,
    /// Block number (height)
    #[serde(rename = "blockNumber")]
    pub block_number: u32,
    /// Block unix timestamp
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: u32,
    /// Transaction identifier
    #[serde(rename = "txID")]
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    pub tx_id: U256,
    /// Transaction origin (signer)
    #[serde(rename = "txOrigin")]
    pub tx_origin: Address,
}

/// Emitted contract event
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// The address of contract which produces the event
    pub address: Address,
    /// Event topics
    #[serde_as(as = "Vec<unhex::HexNum<32, U256>>")]
    pub topics: Vec<U256>,
    /// Event data
    #[serde_as(as = "unhex::Hex")]
    pub data: Bytes,
}

/// Single transfer during the contract call
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block number (height)
    pub number: u32,
    /// Block identifier
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    pub id: U256,
    /// RLP encoded block size in bytes
    pub size: u32,
    /// Parent block ID
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    #[serde(rename = "parentID")]
    pub parent_id: U256,
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
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    #[serde(rename = "txsRoot")]
    pub txs_root: U256,
    /// Supported txs features bitset
    #[serde(rename = "txsFeatures")]
    pub txs_features: u32,
    /// Root hash of accounts state
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    #[serde(rename = "stateRoot")]
    pub state_root: U256,
    /// Root hash of transaction receipts
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    #[serde(rename = "receiptsRoot")]
    pub receipts_root: U256,
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

impl BlockInfo {
    pub const fn block_ref(&self) -> u64 {
        //! Extract blockRef for transaction.
        self.id.as_limbs()[3]
    }
}

/// Transaction data included in the block extended details.
///
/// Combines [`ExtendedTransaction`] and [`Receipt`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    #[serde_as(as = "Vec<unhex::HexNum<32, U256>>")]
    transactions: Vec<U256>,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
struct BlockExtendedResponse {
    #[serde(flatten)]
    base: BlockInfo,
    transactions: Vec<BlockTransaction>,
}

/// Block reference: a way to identify the block on the chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockReference {
    /// Latest: already approved by some node, but not finalized yet.
    Best,
    /// Finalized: block is frozen on chain.
    Finalized,
    /// Block ordinal number (1..)
    Number(u64),
    /// Block ID
    ID(U256),
}

impl BlockReference {
    fn as_query_param(&self) -> String {
        match self {
            BlockReference::Best => "best".to_string(),
            BlockReference::Finalized => "finalized".to_string(),
            BlockReference::Number(num) => format!("0x{num:02x}"),
            BlockReference::ID(id) => format!("0x{id:064x}"),
        }
    }
}

/// Account details
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountInfo {
    /// VET balance
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    pub balance: U256,
    /// VTHO balance
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    pub energy: U256,
    /// Is a contract?
    #[serde(rename = "hasCode")]
    pub has_code: bool,
}

#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
struct AccountCodeResponse {
    #[serde_as(as = "unhex::Hex")]
    code: Bytes,
}
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
struct AccountStorageResponse {
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    value: U256,
}
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Serialize)]
struct TransactionBroadcastRequest {
    #[serde_as(as = "unhex::Hex")]
    raw: Bytes,
}
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Deserialize)]
struct TransactionIdResponse {
    #[serde_as(as = "unhex::HexNum<32, U256>")]
    id: U256,
}

/// Transaction execution simulation request
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimulateCallRequest {
    /// Clauses of transaction
    pub clauses: Vec<Clause>,
    /// Maximal amount of gas
    pub gas: u64,
    /// Gas price
    #[serde_as(as = "serde_with::DisplayFromStr")]
    #[serde(rename = "gasPrice")]
    pub gas_price: u64,
    /// Caller address
    pub caller: Address,
    /// ???
    #[serde_as(as = "serde_with::DisplayFromStr")]
    #[serde(rename = "provedWork")]
    pub proved_work: u64,
    /// Gas payer address
    #[serde(rename = "gasPayer")]
    pub gas_payer: Address,
    /// Expiration (in blocks)
    pub expiration: u32,
    /// Block reference to count expiration from.
    #[serde_as(as = "unhex::HexNum<8, u64>")]
    #[serde(rename = "blockRef")]
    pub block_ref: u64,
}

/// `eth_call` (pure or view function call without on-chain transaction) request
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EthCallRequest {
    /// Clauses of transaction
    pub clauses: Vec<Clause>,
    /// Maximal amount of gas
    pub gas: Option<u64>,
    /// Gas price
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<u64>,
    /// Caller address
    pub caller: Option<Address>,
}

impl EthCallRequest {
    pub fn from_clause(clause: Clause) -> Self {
        //! Shortcut for a single clause request.
        Self {
            clauses: vec![clause],
            gas: None,
            gas_price: None,
            caller: None,
        }
    }
}

/// Transaction execution simulation request
#[serde_with::serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SimulateCallResponse {
    /// Output data
    #[serde_as(as = "unhex::Hex")]
    pub data: Bytes,
    /// Emitted events
    pub events: Vec<Event>,
    /// Executed transfers
    pub transfers: Vec<Transfer>,
    /// Gas spent
    #[serde(rename = "gasUsed")]
    pub gas_used: u64,
    /// Will be reverted?
    pub reverted: bool,
    /// Error description returned by VM
    #[serde(rename = "vmError")]
    pub vm_error: String,
}

impl ThorNode {
    /// Chain tag for mainnet
    pub const MAINNET_CHAIN_TAG: u8 = 0x4A;
    /// REST API URL for mainnet (one possible)
    pub const MAINNET_BASE_URL: &'static str = "https://mainnet.vechain.org/";
    /// Chain tag for testnet
    pub const TESTNET_CHAIN_TAG: u8 = 0x27;
    /// REST API URL for testnet (one possible)
    pub const TESTNET_BASE_URL: &'static str = "https://testnet.vechain.org/";

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
        transaction_id: U256,
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
        let path = format!("/transactions/0x{transaction_id:064x}");
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
        transaction_id: U256,
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
        let path = format!("/transactions/0x{transaction_id:064x}");
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
        transaction_id: U256,
    ) -> AResult<Option<(Receipt, ReceiptMeta)>> {
        //! Retrieve a transaction receipt from node given a transaction ID.
        //!
        //! Returns [`None`] for nonexistent or not mined transactions.
        let client = Client::new();
        let path = format!("/transactions/0x{transaction_id:064x}/receipt");
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
    ) -> AResult<Option<(BlockInfo, Vec<U256>)>> {
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

    pub async fn fetch_best_block(&self) -> AResult<(BlockInfo, Vec<U256>)> {
        //! Retrieve a best block from node.
        let info = self.fetch_block(BlockReference::Best).await?;
        Ok(info.ok_or(ValidationError::Unknown("Best block not found".to_string()))?)
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

    pub async fn broadcast_transaction(&self, transaction: &Transaction) -> AResult<U256> {
        //! Broadcast a new [`Transaction`] to the node.
        let client = Client::new();
        let response = client
            .post(self.base_url.join("/transactions")?)
            .json(&TransactionBroadcastRequest {
                raw: transaction.to_broadcastable_bytes()?,
            })
            .send()
            .await?
            .text()
            .await?;
        let decoded: TransactionIdResponse = serde_json::from_str(&response)
            .map_err(|_| ValidationError::BroadcastFailed(response.to_string()))?;
        Ok(decoded.id)
    }

    pub async fn fetch_account(&self, address: Address) -> AResult<AccountInfo> {
        //! Retrieve account details.
        let client = Client::new();
        let path = format!("/accounts/{}", address.to_hex());
        Ok(client
            .get(self.base_url.join(&path)?)
            .send()
            .await?
            .json::<AccountInfo>()
            .await?)
    }

    pub async fn fetch_account_code(&self, address: Address) -> AResult<Option<Bytes>> {
        //! Retrieve account code.
        //!
        //! Returns [`None`] for non-contract accounts.
        let client = Client::new();
        let path = format!("/accounts/{}/code", address.to_hex());
        let response = client
            .get(self.base_url.join(&path)?)
            .send()
            .await?
            .json::<AccountCodeResponse>()
            .await?;
        if response.code.is_empty() {
            Ok(None)
        } else {
            Ok(Some(response.code))
        }
    }

    pub async fn fetch_account_storage(&self, address: Address, key: U256) -> AResult<U256> {
        //! Retrieve account storage at key.
        //!
        //! Returns [`None`] for non-contract accounts or for missing storage keys.
        if key.is_zero() {
            return Err(Box::new(ValidationError::ZeroStorageKey));
        }
        let client = Client::new();
        let path = format!("/accounts/{}/storage/0x{:064x}", address.to_hex(), key);
        let response = client
            .get(self.base_url.join(&path)?)
            .send()
            .await?
            .json::<AccountStorageResponse>()
            .await?;
        Ok(response.value)
    }

    pub async fn simulate_execution(
        &self,
        request: SimulateCallRequest,
    ) -> AResult<Vec<SimulateCallResponse>> {
        //! Simulate a transaction execution.
        //!
        //! This is an equivalent of eth_call and can be used to call `pure` and
        //! `view` functions without broadcasting a transaction. See
        //! [`eth_call`] for a better interface
        let client = Client::new();
        let response = client
            .post(self.base_url.join("/accounts/*")?)
            .json(&request)
            .send()
            .await?
            .json::<Vec<SimulateCallResponse>>()
            .await?;
        Ok(response)
    }

    pub async fn eth_call_advanced(
        &self,
        request: EthCallRequest,
        block_ref: BlockReference,
    ) -> AResult<Vec<SimulateCallResponse>> {
        //! Call a `pure` or `view` function as defined by `clause.data`,
        //! possibly providing additional options.
        let client = Client::new();
        let response = client
            .post(self.base_url.join("/accounts/*")?)
            .query(&[("revision", block_ref.as_query_param())])
            .json(&request)
            .send()
            .await?
            .json::<Vec<SimulateCallResponse>>()
            .await?;
        Ok(response)
    }

    pub async fn eth_call(&self, clause: Clause, block_ref: BlockReference) -> AResult<Bytes> {
        //! Call a `pure` or `view` function as defined by `clause.data`.
        //!
        //! Returns byte representation of the returned data, error on revert
        //! or when unexpected payload is returned
        let mut response = self
            .eth_call_advanced(EthCallRequest::from_clause(clause), block_ref)
            .await?;
        if response.len() > 1 {
            return Err("Multiple responses".into());
        } else if response.is_empty() {
            return Err("Empty response".into());
        }
        let tx = response.remove(0);
        if tx.reverted {
            return Err("Transaction reverted".into());
        }
        Ok(tx.data)
    }
}
