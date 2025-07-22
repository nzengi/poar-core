//! POAR Wallet Transaction Manager
//! 
//! This module provides transaction management for POAR wallet with:
//! - Transaction building and signing
//! - Network submission and monitoring
//! - Fee estimation and optimization
//! - Transaction history and status tracking
//! - Batch transaction support
//! - Gas optimization

use crate::types::{Transaction, Address, Signature, Hash};
use crate::types::token::TokenUnit;
use crate::types::transaction::TransactionType;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

/// Transaction status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Confirmed { block_height: u64, confirmations: u32 },
    Failed { error: String },
    Dropped,
}

/// Fee estimation strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeeStrategy {
    Low,
    Medium,
    High,
    Custom { gas_price: u64, gas_limit: u64 },
}

/// Transaction metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMetadata {
    pub transaction_type: TransactionType,
    pub fee_strategy: FeeStrategy,
    pub created_at: u64,
    pub submitted_at: Option<u64>,
    pub confirmed_at: Option<u64>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub priority: TransactionPriority,
}

impl Default for TransactionMetadata {
    fn default() -> Self {
        Self {
            transaction_type: TransactionType::Transfer,
            fee_strategy: FeeStrategy::Medium,
            created_at: 0,
            submitted_at: None,
            confirmed_at: None,
            retry_count: 0,
            max_retries: 3,
            priority: TransactionPriority::Normal,
        }
    }
}

/// Transaction priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionPriority {
    Low,
    Normal,
    High,
    Urgent,
}

/// Transaction manager errors
#[derive(Debug)]
pub enum TransactionManagerError {
    InsufficientFunds { required: u64, available: u64 },
    InvalidTransaction(String),
    GasLimitExceeded(u64),
    NonceReused(u64),
    TransactionUnderpriced,
    NetworkError(String),
    Timeout(String),
    SigningError(String),
    SerializationError(String),
    Unknown(String),
}

impl fmt::Display for TransactionManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionManagerError::InsufficientFunds { required, available } => {
                write!(f, "Insufficient funds. Required: {}, Available: {}", required, available)
            }
            TransactionManagerError::InvalidTransaction(msg) => write!(f, "Invalid transaction: {}", msg),
            TransactionManagerError::GasLimitExceeded(limit) => write!(f, "Gas limit exceeded: {}", limit),
            TransactionManagerError::NonceReused(nonce) => write!(f, "Nonce reused: {}", nonce),
            TransactionManagerError::TransactionUnderpriced => write!(f, "Transaction underpriced"),
            TransactionManagerError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            TransactionManagerError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            TransactionManagerError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            TransactionManagerError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            TransactionManagerError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for TransactionManagerError {}

/// POAR Transaction Manager
pub struct TransactionManager {
    /// Pending transactions
    pending_transactions: Arc<Mutex<HashMap<Hash, PendingTransaction>>>,
    /// Transaction history
    transaction_history: Arc<Mutex<Vec<TransactionRecord>>>,
    /// Network connection
    network_client: NetworkClient,
    /// Fee estimator
    fee_estimator: FeeEstimator,
    /// Transaction builder
    transaction_builder: TransactionBuilder,
    /// Configuration
    config: TransactionManagerConfig,
}

/// Pending transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    pub transaction: Transaction,
    pub metadata: TransactionMetadata,
    pub status: TransactionStatus,
    pub last_retry: Option<u64>, // Changed from Instant to u64
}

/// Transaction record for history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub hash: Hash,
    pub transaction: Transaction,
    pub metadata: TransactionMetadata,
    pub status: TransactionStatus,
    pub block_height: Option<u64>,
    pub confirmations: Option<u32>,
    pub fee_paid: u64,
    pub gas_used: Option<u64>,
}

/// Network client for transaction submission
pub struct NetworkClient {
    pub endpoint: String,
    pub timeout: Duration,
    pub retry_attempts: u32,
}

/// Fee estimator for gas price calculation
pub struct FeeEstimator {
    pub base_fee: u64,
    pub priority_fee: u64,
    pub max_fee: u64,
    pub gas_limit_multiplier: f64,
}

/// Transaction builder for creating transactions
pub struct TransactionBuilder {
    pub default_gas_limit: u64,
    pub max_gas_limit: u64,
    pub gas_price_multiplier: f64,
}

/// Transaction manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionManagerConfig {
    pub default_fee_strategy: FeeStrategy,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub timeout_seconds: u64,
    pub auto_confirmations: u32,
    pub batch_size: u32,
    pub enable_fee_optimization: bool,
    pub enable_gas_optimization: bool,
}

impl TransactionManager {
    /// Create new transaction manager
    pub fn new() -> Self {
        let network_client = NetworkClient {
            endpoint: "http://localhost:8545".to_string(),
            timeout: Duration::from_secs(30),
            retry_attempts: 3,
        };

        let fee_estimator = FeeEstimator {
            base_fee: 1,
            priority_fee: 1,
            max_fee: 100,
            gas_limit_multiplier: 1.1,
        };

        let transaction_builder = TransactionBuilder {
            default_gas_limit: 21000,
            max_gas_limit: 1000000,
            gas_price_multiplier: 1.2,
        };

        let config = TransactionManagerConfig {
            default_fee_strategy: FeeStrategy::Medium,
            max_retries: 3,
            retry_delay_ms: 1000,
            timeout_seconds: 30,
            auto_confirmations: 12,
            batch_size: 10,
            enable_fee_optimization: true,
            enable_gas_optimization: true,
        };

        Self {
            pending_transactions: Arc::new(Mutex::new(HashMap::new())),
            transaction_history: Arc::new(Mutex::new(Vec::new())),
            network_client,
            fee_estimator,
            transaction_builder,
            config,
        }
    }

    /// Create and submit a transfer transaction
    pub fn transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: u64,
        token: TokenUnit,
        fee_strategy: Option<FeeStrategy>,
    ) -> Result<Hash, TransactionManagerError> {
        let fee_strategy = fee_strategy.unwrap_or(self.config.default_fee_strategy.clone());
        
        let transaction = self.transaction_builder.build_transfer(
            from,
            to,
            amount,
            token,
            &fee_strategy,
        )?;

        let metadata = TransactionMetadata {
            transaction_type: TransactionType::Transfer,
            fee_strategy,
            created_at: Self::current_timestamp(),
            submitted_at: None,
            confirmed_at: None,
            retry_count: 0,
            max_retries: self.config.max_retries,
            priority: TransactionPriority::Normal,
        };

        self.submit_transaction(transaction, metadata)
    }

    /// Create and submit a staking transaction
    pub fn stake(
        &mut self,
        from: Address,
        amount: u64,
        fee_strategy: Option<FeeStrategy>,
    ) -> Result<Hash, TransactionManagerError> {
        let fee_strategy = fee_strategy.unwrap_or(self.config.default_fee_strategy.clone());
        
        let transaction = self.transaction_builder.build_stake(
            from,
            amount,
            &fee_strategy,
        )?;

        let metadata = TransactionMetadata {
            transaction_type: TransactionType::ValidatorStaking,
            fee_strategy,
            created_at: Self::current_timestamp(),
            submitted_at: None,
            confirmed_at: None,
            retry_count: 0,
            max_retries: self.config.max_retries,
            priority: TransactionPriority::Normal,
        };

        self.submit_transaction(transaction, metadata)
    }

    /// Create and submit an unstaking transaction
    pub fn unstake(
        &mut self,
        from: Address,
        amount: u64,
        fee_strategy: Option<FeeStrategy>,
    ) -> Result<Hash, TransactionManagerError> {
        let fee_strategy = fee_strategy.unwrap_or(self.config.default_fee_strategy.clone());
        
        let transaction = self.transaction_builder.build_unstake(
            from,
            amount,
            &fee_strategy,
        )?;

        let metadata = TransactionMetadata {
            transaction_type: TransactionType::ValidatorUnstaking,
            fee_strategy,
            created_at: Self::current_timestamp(),
            submitted_at: None,
            confirmed_at: None,
            retry_count: 0,
            max_retries: self.config.max_retries,
            priority: TransactionPriority::Normal,
        };

        self.submit_transaction(transaction, metadata)
    }

    /// Create and submit a governance vote transaction
    pub fn vote_on_proposal(
        &mut self,
        from: Address,
        proposal_id: u64,
        vote: bool,
        fee_strategy: Option<FeeStrategy>,
    ) -> Result<Hash, TransactionManagerError> {
        let fee_strategy = fee_strategy.unwrap_or(self.config.default_fee_strategy.clone());
        
        let transaction = self.transaction_builder.build_governance_vote(
            from,
            proposal_id,
            vote,
            &fee_strategy,
        )?;

        let metadata = TransactionMetadata {
            transaction_type: TransactionType::System,
            fee_strategy,
            created_at: Self::current_timestamp(),
            submitted_at: None,
            confirmed_at: None,
            retry_count: 0,
            max_retries: self.config.max_retries,
            priority: TransactionPriority::High,
        };

        self.submit_transaction(transaction, metadata)
    }

    /// Submit a transaction to the network
    pub fn submit_transaction(
        &mut self,
        transaction: Transaction,
        metadata: TransactionMetadata,
    ) -> Result<Hash, TransactionManagerError> {
        // Calculate transaction hash
        let tx_hash = transaction.calculate_hash();
        
        // Add to pending transactions
        {
            let mut pending = self.pending_transactions.lock()
                .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
            pending.insert(tx_hash, PendingTransaction {
                transaction: transaction.clone(),
                metadata: metadata.clone(),
                status: TransactionStatus::Pending,
                last_retry: None,
            });
        }

        // Submit to network
        self.network_client.submit_transaction(&transaction)?;

        // Update metadata
        {
            let mut pending = self.pending_transactions.lock()
                .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
            if let Some(pending_tx) = pending.get_mut(&tx_hash) {
                pending_tx.metadata.submitted_at = Some(Self::current_timestamp());
            }
        }

        Ok(tx_hash)
    }

    /// Get transaction status
    pub fn get_transaction_status(&self, hash: &Hash) -> Result<TransactionStatus, TransactionManagerError> {
        // Check pending transactions first
        {
            let pending = self.pending_transactions.lock()
                .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
            if let Some(pending_tx) = pending.get(hash) {
                return Ok(pending_tx.status.clone());
            }
        }

        // Check transaction history
        {
            let history = self.transaction_history.lock()
                .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
            for record in history.iter() {
                if record.hash == *hash {
                    return Ok(record.status.clone());
                }
            }
        }

        // Query network for transaction status
        self.network_client.get_transaction_status(hash)
    }

    /// Get transaction history
    pub fn get_transaction_history(&self, address: &Address, limit: Option<u32>) -> Result<Vec<TransactionRecord>, TransactionManagerError> {
        let history = self.transaction_history.lock()
            .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
        
        let mut filtered_history: Vec<TransactionRecord> = history
            .iter()
            .filter(|record| record.transaction.from == *address || record.transaction.to == *address)
            .cloned()
            .collect();

        // Sort by creation time (newest first)
        filtered_history.sort_by(|a, b| b.metadata.created_at.cmp(&a.metadata.created_at));

        // Apply limit if specified
        if let Some(limit) = limit {
            filtered_history.truncate(limit as usize);
        }

        Ok(filtered_history)
    }

    /// Estimate transaction fee
    pub fn estimate_fee(
        &self,
        transaction_type: &TransactionType,
        fee_strategy: &FeeStrategy,
    ) -> Result<u64, TransactionManagerError> {
        self.fee_estimator.estimate_fee(transaction_type, fee_strategy)
    }

    /// Get pending transactions
    pub fn get_pending_transactions(&self) -> Result<Vec<PendingTransaction>, TransactionManagerError> {
        let pending = self.pending_transactions.lock()
            .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
        
        Ok(pending.values().cloned().collect())
    }

    /// Cancel a pending transaction
    pub fn cancel_transaction(&mut self, hash: &Hash) -> Result<(), TransactionManagerError> {
        let mut pending = self.pending_transactions.lock()
            .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
        
        if let Some(pending_tx) = pending.remove(hash) {
            // Add to history as cancelled
            let record = TransactionRecord {
                hash: *hash,
                transaction: pending_tx.transaction,
                metadata: pending_tx.metadata,
                status: TransactionStatus::Dropped,
                block_height: None,
                confirmations: None,
                fee_paid: 0,
                gas_used: None,
            };

            let mut history = self.transaction_history.lock()
                .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
            history.push(record);
        }

        Ok(())
    }

    /// Update transaction status from network
    pub fn update_transaction_status(&mut self, hash: &Hash) -> Result<(), TransactionManagerError> {
        let status = self.network_client.get_transaction_status(hash)?;
        
        {
            let mut pending = self.pending_transactions.lock()
                .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
            
            if let Some(pending_tx) = pending.get_mut(hash) {
                pending_tx.status = status.clone();
                
                // If confirmed, move to history
                if let TransactionStatus::Confirmed { .. } = status {
                    let record = TransactionRecord {
                        hash: *hash,
                        transaction: pending_tx.transaction.clone(),
                        metadata: pending_tx.metadata.clone(),
                        status: status.clone(),
                        block_height: None, // Would be set from network response
                        confirmations: None, // Would be set from network response
                        fee_paid: 0, // Would be calculated from transaction
                        gas_used: None, // Would be set from network response
                    };

                    let mut history = self.transaction_history.lock()
                        .map_err(|e| TransactionManagerError::Unknown(e.to_string()))?;
                    history.push(record);
                    
                    // Remove from pending
                    pending.remove(hash);
                }
            }
        }

        Ok(())
    }

    /// Batch submit transactions
    pub fn batch_submit(
        &mut self,
        transactions: Vec<(Transaction, TransactionMetadata)>,
    ) -> Result<Vec<Hash>, TransactionManagerError> {
        let mut hashes = Vec::new();
        
        for (transaction, metadata) in transactions {
            let hash = self.submit_transaction(transaction, metadata)?;
            hashes.push(hash);
        }

        Ok(hashes)
    }

    // Helper methods

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl NetworkClient {
    fn submit_transaction(&self, transaction: &Transaction) -> Result<(), TransactionManagerError> {
        // Simulate network submission
        // In production, this would make an HTTP request to the node
        println!("Submitting transaction to network: {}", transaction.calculate_hash());
        Ok(())
    }

    fn get_transaction_status(&self, hash: &Hash) -> Result<TransactionStatus, TransactionManagerError> {
        // Simulate network query
        // In production, this would query the blockchain
        println!("Querying transaction status: {}", hash);
        Ok(TransactionStatus::Pending)
    }
}

impl FeeEstimator {
    fn estimate_fee(
        &self,
        transaction_type: &TransactionType,
        fee_strategy: &FeeStrategy,
    ) -> Result<u64, TransactionManagerError> {
        let base_gas = match transaction_type {
            TransactionType::Transfer => 21000,
            TransactionType::ValidatorStaking => 50000,
            TransactionType::ValidatorUnstaking => 50000,
            TransactionType::System => 30000,
            TransactionType::ContractDeployment => 100000,
            TransactionType::ContractCall => 30000,
        };

        let gas_price = match fee_strategy {
            FeeStrategy::Low => self.base_fee,
            FeeStrategy::Medium => self.base_fee * 2,
            FeeStrategy::High => self.base_fee * 4,
            FeeStrategy::Custom { gas_price, .. } => *gas_price,
        };

        Ok(base_gas * gas_price)
    }
}

impl TransactionBuilder {
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn build_transfer(
        &self,
        from: Address,
        to: Address,
        amount: u64,
        token: TokenUnit,
        fee_strategy: &FeeStrategy,
    ) -> Result<Transaction, TransactionManagerError> {
        let (gas_limit, gas_price) = self.calculate_gas_params(fee_strategy, 21000)?;
        
        let mut transaction = Transaction {
            from,
            to,
            amount,
            gas_limit,
            gas_price,
            nonce: 0, // Would be fetched from network
            data: Vec::new(),
            signature: Signature::dummy(),
            hash: Hash::zero(), // Will be calculated
            fee: 0, // Will be calculated
            timestamp: Self::current_timestamp(),
            tx_type: TransactionType::Transfer,
        };
        
        // Calculate hash and fee
        transaction.hash = transaction.calculate_hash();
        transaction.fee = gas_limit * gas_price;
        
        Ok(transaction)
    }

    fn build_stake(
        &self,
        from: Address,
        amount: u64,
        fee_strategy: &FeeStrategy,
    ) -> Result<Transaction, TransactionManagerError> {
        let (gas_limit, gas_price) = self.calculate_gas_params(fee_strategy, 50000)?;
        
        let data = vec![0x01]; // Stake operation code
        
        let mut transaction = Transaction {
            from,
            to: Address::zero(), // Contract address
            amount,
            gas_limit,
            gas_price,
            nonce: 0, // Would be fetched from network
            data,
            signature: Signature::dummy(),
            hash: Hash::zero(), // Will be calculated
            fee: 0, // Will be calculated
            timestamp: Self::current_timestamp(),
            tx_type: TransactionType::ValidatorStaking,
        };
        
        // Calculate hash and fee
        transaction.hash = transaction.calculate_hash();
        transaction.fee = gas_limit * gas_price;
        
        Ok(transaction)
    }

    fn build_unstake(
        &self,
        from: Address,
        amount: u64,
        fee_strategy: &FeeStrategy,
    ) -> Result<Transaction, TransactionManagerError> {
        let (gas_limit, gas_price) = self.calculate_gas_params(fee_strategy, 50000)?;
        
        let data = vec![0x02]; // Unstake operation code
        
        let mut transaction = Transaction {
            from,
            to: Address::zero(), // Contract address
            amount,
            gas_limit,
            gas_price,
            nonce: 0, // Would be fetched from network
            data,
            signature: Signature::dummy(),
            hash: Hash::zero(), // Will be calculated
            fee: 0, // Will be calculated
            timestamp: Self::current_timestamp(),
            tx_type: TransactionType::ValidatorUnstaking,
        };
        
        // Calculate hash and fee
        transaction.hash = transaction.calculate_hash();
        transaction.fee = gas_limit * gas_price;
        
        Ok(transaction)
    }

    fn build_governance_vote(
        &self,
        from: Address,
        proposal_id: u64,
        vote: bool,
        fee_strategy: &FeeStrategy,
    ) -> Result<Transaction, TransactionManagerError> {
        let (gas_limit, gas_price) = self.calculate_gas_params(fee_strategy, 30000)?;
        
        let mut data = vec![0x03]; // Vote operation code
        data.extend_from_slice(&proposal_id.to_le_bytes());
        data.push(if vote { 1 } else { 0 });
        
        let mut transaction = Transaction {
            from,
            to: Address::zero(), // Governance contract address
            amount: 0,
            gas_limit,
            gas_price,
            nonce: 0, // Would be fetched from network
            data,
            signature: Signature::dummy(),
            hash: Hash::zero(), // Will be calculated
            fee: 0, // Will be calculated
            timestamp: Self::current_timestamp(),
            tx_type: TransactionType::System,
        };
        
        // Calculate hash and fee
        transaction.hash = transaction.calculate_hash();
        transaction.fee = gas_limit * gas_price;
        
        Ok(transaction)
    }

    fn calculate_gas_params(
        &self,
        fee_strategy: &FeeStrategy,
        base_gas: u64,
    ) -> Result<(u64, u64), TransactionManagerError> {
        let gas_limit = (base_gas as f64 * self.gas_price_multiplier) as u64;
        
        if gas_limit > self.max_gas_limit {
            return Err(TransactionManagerError::GasLimitExceeded(self.max_gas_limit));
        }

        let gas_price = match fee_strategy {
            FeeStrategy::Low => 1,
            FeeStrategy::Medium => 2,
            FeeStrategy::High => 4,
            FeeStrategy::Custom { gas_price, .. } => *gas_price,
        };

        Ok((gas_limit, gas_price))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Address;

    #[test]
    fn test_transaction_manager_creation() {
        let manager = TransactionManager::new();
        assert_eq!(manager.config.max_retries, 3);
    }

    #[test]
    fn test_transfer_transaction() {
        let mut manager = TransactionManager::new();
        let from = Address::from_slice(&[0u8; 32]).unwrap();
        let to = Address::from_slice(&[1u8; 32]).unwrap();
        
        let result = manager.transfer(from, to, 1000, TokenUnit::Poar, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fee_estimation() {
        let manager = TransactionManager::new();
        let transaction_type = TransactionType::Transfer;
        let fee_strategy = FeeStrategy::Medium;
        
        let result = manager.estimate_fee(&transaction_type, &fee_strategy);
        assert!(result.is_ok());
    }
} 