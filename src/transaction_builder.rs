use alloy::primitives::ruint::UintTryFrom;
use rand::Rng as _;

use crate::address::Address;
use crate::network::ThorNode;
use crate::rlp::Bytes;
use crate::transactions::{Clause, Reserved, Transaction};
use crate::U256;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct TransactionTemplate {
    block_ref: Option<u64>,
    expiration: Option<u32>,
    clauses: Vec<Clause>,
    gas_price_coef: Option<u8>,
    gas: Option<u64>,
    depends_on: Option<U256>,
    nonce: Option<u64>,
    delegated: bool,
}

/// Transaction builder allows to create and prepare transactions
/// with minimal developers efforts.
#[derive(Clone, Debug)]
pub struct TransactionBuilder {
    node: ThorNode,
    template: TransactionTemplate,
}

impl TransactionBuilder {
    #[must_use]
    pub fn new(node: ThorNode) -> Self {
        //! Create a new builder.
        Self {
            node,
            template: TransactionTemplate::default(),
        }
    }
    #[must_use]
    pub const fn delegated(mut self) -> Self {
        //! Make a transaction delegated.
        self.template.delegated = true;
        self
    }
    #[must_use]
    pub const fn nonce(mut self, nonce: u64) -> Self {
        //! Set a nonce for transaction.
        self.template.nonce = Some(nonce);
        self
    }
    #[must_use]
    pub const fn depends_on(mut self, depends_on: U256) -> Self {
        //! Mark a transaction as dependent on another one.
        self.template.depends_on = Some(depends_on);
        self
    }
    #[must_use]
    pub const fn gas(mut self, gas: u64) -> Self {
        //! Set maximal gas amount for transaction.
        self.template.gas = Some(gas);
        self
    }
    #[must_use]
    pub const fn gas_price_coef(mut self, gas_price_coef: u8) -> Self {
        //! Set gas price coefficient for transaction.
        self.template.gas_price_coef = Some(gas_price_coef);
        self
    }
    #[must_use]
    pub const fn expiration(mut self, expiration: u32) -> Self {
        //! Set expiration for transaction in blocks, starting from `block_ref`.
        self.template.expiration = Some(expiration);
        self
    }
    #[must_use]
    pub const fn block_ref(mut self, block_ref: u64) -> Self {
        //! Set `block_ref` for transaction to count `expiration` from.
        self.template.block_ref = Some(block_ref);
        self
    }
    #[must_use]
    pub fn add_transfer<T>(self, recipient: Address, value: T) -> Self
    where
        U256: UintTryFrom<T>,
    {
        //! Add a simple transfer to clauses.
        self.add_clause(Clause {
            to: Some(recipient),
            value: U256::from(value),
            data: Bytes::new(),
        })
    }
    #[must_use]
    pub fn add_contract_create(self, contract_bytes: Bytes) -> Self {
        //! Add a contract creation clause.
        self.add_clause(Clause {
            to: None,
            value: U256::ZERO,
            data: contract_bytes,
        })
    }
    #[must_use]
    pub fn add_contract_call(self, contract_address: Address, call_bytes: Bytes) -> Self {
        //! Add a contract method call clause.
        self.add_clause(Clause {
            to: Some(contract_address),
            value: U256::ZERO,
            data: call_bytes,
        })
    }
    #[must_use]
    pub fn add_clause(mut self, clause: Clause) -> Self {
        //! Add an arbitrary, user-provided clause.
        self.template.clauses.push(clause);
        self
    }

    pub async fn build(&self) -> Result<Transaction, TransactionBuilderError> {
        //! Prepare a `Transaction`. This may perform a network request
        //! to identify appropriate parameters.
        if self.template.clauses.is_empty() {
            return Err(TransactionBuilderError::EmptyTransaction);
        }
        let block_ref = match self.template.block_ref {
            Some(r) => r,
            None => self
                .node
                .fetch_best_block()
                .await
                .map_err(|_| TransactionBuilderError::NetworkError)?
                .0
                .block_ref(),
        };
        let mut tx = Transaction {
            chain_tag: self.node.chain_tag,
            block_ref,
            expiration: self.template.expiration.unwrap_or(128),
            clauses: self.template.clauses.clone(),
            gas_price_coef: self.template.gas_price_coef.unwrap_or(0),
            gas: self.template.gas.unwrap_or(0),
            depends_on: self.template.depends_on,
            nonce: self.template.nonce.unwrap_or_else(|| {
                let mut rng = rand::rng();
                rng.random::<u64>()
            }),
            reserved: self.template.delegated.then(Reserved::new_delegated),
            signature: None,
        };
        if self.template.gas.is_some() {
            Ok(tx)
        } else if tx.clauses.iter().all(|clause| clause.data.is_empty()) {
            tx.gas = tx.intrinsic_gas();
            Ok(tx)
        } else {
            Err(TransactionBuilderError::CannotEstimateGas)
        }
    }
}

/// Transaction creation errors
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionBuilderError {
    /// Network error (failed to fetch data from node)
    NetworkError,
    /// No clauses provided
    EmptyTransaction,
    /// Transaction clauses involve contract interaction, and gas was not provided.
    CannotEstimateGas,
}

impl std::error::Error for TransactionBuilderError {}
impl std::fmt::Display for TransactionBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError => f.write_str("Failed to retrieve data from network"),
            Self::EmptyTransaction => f.write_str("Cannot build an empty transaction - make sure to add at least one clause first."),
            Self::CannotEstimateGas => f.write_str("Transaction clauses involve contract interaction, please provide gas amount explicitly."),
        }
    }
}
