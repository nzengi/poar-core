// POAR Transaction Types - Placeholder
// TODO: Implement full transaction structure

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, BTreeMap};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::{Hash, Address, Signature};

/// POAR transaction with ZK-proof support
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    /// Unique transaction hash
    pub hash: Hash,
    /// Sender address
    pub from: Address,
    /// Receiver address
    pub to: Address,
    /// Amount to transfer (in smallest unit)
    pub amount: u64,
    /// Transaction fee (in smallest unit)
    pub fee: u64,
    /// Gas limit for execution
    pub gas_limit: u64,
    /// Gas price (fee per gas unit)
    pub gas_price: u64,
    /// Transaction nonce (prevents replay attacks)
    pub nonce: u64,
    /// Transaction data/payload
    pub data: Vec<u8>,
    /// Sender's signature
    pub signature: Signature,
    /// Unix timestamp when transaction was created
    pub timestamp: u64,
    /// Transaction type
    pub tx_type: TransactionType,
}

/// Transaction input for UTXO model (if we choose UTXO)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionInput {
    /// Hash of the previous transaction
    pub previous_tx_hash: Hash,
    /// Index of the output being spent
    pub output_index: u32,
    /// Signature script
    pub signature_script: Vec<u8>,
    /// Sequence number
    pub sequence: u32,
}

/// Transaction output for UTXO model
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransactionOutput {
    /// Amount in this output
    pub amount: u64,
    /// Public key script (recipient)
    pub pubkey_script: Vec<u8>,
}

/// Transaction types supported by POAR
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    /// Standard value transfer
    Transfer,
    /// Smart contract deployment
    ContractDeployment,
    /// Smart contract call
    ContractCall,
    /// Validator staking
    ValidatorStaking,
    /// Validator unstaking
    ValidatorUnstaking,
    /// System transaction (rewards, etc.)
    System,
}

/// Transaction validation result
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionValidationResult {
    Valid,
    InvalidSignature,
    InvalidNonce,
    InsufficientBalance,
    InsufficientGas,
    InvalidRecipient,
    InvalidAmount,
    InvalidFee,
    DataTooLarge,
    Expired,
}

/// Transaction pool (mempool) for managing pending transactions
#[derive(Debug, Default)]
pub struct TransactionPool {
    /// Pending transactions by hash
    transactions: HashMap<Hash, Transaction>,
    /// Transactions by sender address (for nonce validation)
    by_sender: HashMap<Address, BTreeMap<u64, Hash>>,
    /// Transactions sorted by gas price (priority queue)
    by_gas_price: BTreeMap<u64, Vec<Hash>>,
    /// Pool configuration
    config: PoolConfig,
    /// Pool statistics
    stats: PoolStats,
}

/// Transaction pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of transactions in pool
    pub max_pool_size: usize,
    /// Maximum transactions per account
    pub max_per_account: usize,
    /// Minimum gas price to accept
    pub min_gas_price: u64,
    /// Maximum transaction data size
    pub max_data_size: usize,
    /// Transaction expiry time in seconds
    pub expiry_time: u64,
}

/// Transaction pool statistics
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Total transactions processed
    pub total_processed: u64,
    /// Total transactions rejected
    pub total_rejected: u64,
    /// Current pool size
    pub current_size: usize,
    /// Average gas price
    pub avg_gas_price: u64,
}

/// Transaction fee calculator
pub struct FeeCalculator {
    /// Base fee per transaction
    pub base_fee: u64,
    /// Fee per byte of data
    pub data_fee_per_byte: u64,
    /// Network congestion multiplier
    pub congestion_multiplier: f64,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(
        from: Address,
        to: Address,
        amount: u64,
        fee: u64,
        gas_limit: u64,
        gas_price: u64,
        nonce: u64,
        data: Vec<u8>,
        tx_type: TransactionType,
    ) -> Self {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let mut tx = Self {
            hash: Hash::zero(), // Will be calculated
            from,
            to,
            amount,
            fee,
            gas_limit,
            gas_price,
            nonce,
            data,
            signature: Signature::default(), // Will be signed later
            timestamp,
            tx_type,
        };
        
        tx.hash = tx.calculate_hash();
        tx
    }

    /// Calculate transaction hash
    pub fn calculate_hash(&self) -> Hash {
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(self.from.as_bytes());
        hash_input.extend_from_slice(self.to.as_bytes());
        hash_input.extend_from_slice(&self.amount.to_le_bytes());
        hash_input.extend_from_slice(&self.fee.to_le_bytes());
        hash_input.extend_from_slice(&self.gas_limit.to_le_bytes());
        hash_input.extend_from_slice(&self.gas_price.to_le_bytes());
        hash_input.extend_from_slice(&self.nonce.to_le_bytes());
        hash_input.extend_from_slice(&self.data);
        hash_input.extend_from_slice(&self.timestamp.to_le_bytes());
        
        // Add transaction type
        let tx_type_byte = match self.tx_type {
            TransactionType::Transfer => 0u8,
            TransactionType::ContractDeployment => 1u8,
            TransactionType::ContractCall => 2u8,
            TransactionType::ValidatorStaking => 3u8,
            TransactionType::ValidatorUnstaking => 4u8,
            TransactionType::System => 5u8,
        };
        hash_input.push(tx_type_byte);
        
        Hash::hash(&hash_input)
    }

    /// Sign transaction with private key
    pub fn sign(&mut self, signature: Signature) {
        self.signature = signature;
    }

    /// Basic validation (structure, bounds, etc.)
    pub fn validate_basic(&self) -> bool {
        // Check amount is not zero for transfers
        if matches!(self.tx_type, TransactionType::Transfer) && self.amount == 0 {
            return false;
        }

        // Check gas limit is reasonable
        if self.gas_limit < 21000 || self.gas_limit > 10_000_000 {
            return false;
        }

        // Check gas price is not zero
        if self.gas_price == 0 {
            return false;
        }

        // Check data size
        if self.data.len() > 1024 * 1024 {
            return false; // Max 1MB data
        }

        // Check addresses are not zero for transfers
        if matches!(self.tx_type, TransactionType::Transfer) && 
           (self.from.is_zero() || self.to.is_zero()) {
            return false;
        }

        // Check hash integrity
        let calculated_hash = self.calculate_hash();
        if self.hash != calculated_hash {
            return false;
        }

        true
    }

    /// Comprehensive validation with state context
    pub fn validate(&self, sender_balance: u64, sender_nonce: u64) -> TransactionValidationResult {
        // Basic validation first
        if !self.validate_basic() {
            return TransactionValidationResult::InvalidAmount;
        }

        // Check nonce
        if self.nonce != sender_nonce {
            return TransactionValidationResult::InvalidNonce;
        }

        // Check balance (amount + fee)
        let total_cost = self.amount + self.fee;
        if sender_balance < total_cost {
            return TransactionValidationResult::InsufficientBalance;
        }

        // Check gas fee
        let gas_fee = self.gas_limit * self.gas_price;
        if gas_fee != self.fee {
            return TransactionValidationResult::InvalidFee;
        }

        // Check expiry
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if current_time > self.timestamp + 3600 { // 1 hour expiry
            return TransactionValidationResult::Expired;
        }

        TransactionValidationResult::Valid
    }

    /// Get transaction size in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self).unwrap_or_default().len()
    }

    /// Check if transaction has expired
    pub fn is_expired(&self, expiry_seconds: u64) -> bool {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        current_time > self.timestamp + expiry_seconds
    }

    /// Get transaction priority score (for sorting)
    pub fn priority_score(&self) -> u64 {
        // Higher gas price = higher priority
        self.gas_price
    }
}

impl TransactionPool {
    /// Create new transaction pool
    pub fn new(config: PoolConfig) -> Self {
        Self {
            transactions: HashMap::new(),
            by_sender: HashMap::new(),
            by_gas_price: BTreeMap::new(),
            config,
            stats: PoolStats::default(),
        }
    }

    /// Add transaction to pool
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), String> {
        // Check pool size limit
        if self.transactions.len() >= self.config.max_pool_size {
            return Err("Pool is full".to_string());
        }

        // Check gas price minimum
        if tx.gas_price < self.config.min_gas_price {
            return Err("Gas price too low".to_string());
        }

        // Check data size
        if tx.data.len() > self.config.max_data_size {
            return Err("Transaction data too large".to_string());
        }

        // Check expiry
        if tx.is_expired(self.config.expiry_time) {
            return Err("Transaction expired".to_string());
        }

        // Check per-account limit
        if let Some(sender_txs) = self.by_sender.get(&tx.from) {
            if sender_txs.len() >= self.config.max_per_account {
                return Err("Too many transactions from this account".to_string());
            }
        }

        // Check for duplicate
        if self.transactions.contains_key(&tx.hash) {
            return Err("Transaction already exists".to_string());
        }

        // Add to main pool
        let tx_hash = tx.hash;
        let sender = tx.from;
        let nonce = tx.nonce;
        let gas_price = tx.gas_price;

        self.transactions.insert(tx_hash, tx);

        // Add to sender index
        self.by_sender.entry(sender).or_insert_with(BTreeMap::new).insert(nonce, tx_hash);

        // Add to gas price index
        self.by_gas_price.entry(gas_price).or_insert_with(Vec::new).push(tx_hash);

        // Update stats
        self.stats.total_processed += 1;
        self.stats.current_size = self.transactions.len();
        self.update_avg_gas_price();

        println!("💰 Added transaction to pool: {}", &tx_hash.to_hex()[..8]);
        Ok(())
    }

    /// Remove transaction from pool
    pub fn remove_transaction(&mut self, tx_hash: &Hash) -> Option<Transaction> {
        if let Some(tx) = self.transactions.remove(tx_hash) {
            // Remove from sender index
            if let Some(sender_txs) = self.by_sender.get_mut(&tx.from) {
                sender_txs.remove(&tx.nonce);
                if sender_txs.is_empty() {
                    self.by_sender.remove(&tx.from);
                }
            }

            // Remove from gas price index
            if let Some(gas_price_txs) = self.by_gas_price.get_mut(&tx.gas_price) {
                gas_price_txs.retain(|h| h != tx_hash);
                if gas_price_txs.is_empty() {
                    self.by_gas_price.remove(&tx.gas_price);
                }
            }

            // Update stats
            self.stats.current_size = self.transactions.len();
            self.update_avg_gas_price();

            println!("🗑️  Removed transaction from pool: {}", &tx_hash.to_hex()[..8]);
            Some(tx)
        } else {
            None
        }
    }

    /// Get transactions for block inclusion (highest gas price first)
    pub fn get_transactions_for_block(&self, max_transactions: usize, max_gas: u64) -> Vec<Transaction> {
        let mut selected = Vec::new();
        let mut total_gas = 0u64;

        // Iterate through transactions by gas price (highest first)
        for (gas_price, tx_hashes) in self.by_gas_price.iter().rev() {
            for tx_hash in tx_hashes {
                if let Some(tx) = self.transactions.get(tx_hash) {
                    // Check gas limit
                    if total_gas + tx.gas_limit > max_gas {
                        continue;
                    }

                    // Check transaction count
                    if selected.len() >= max_transactions {
                        return selected;
                    }

                    selected.push(tx.clone());
                    total_gas += tx.gas_limit;
                }
            }
        }

        selected
    }

    /// Get pending transactions by sender
    pub fn get_pending_by_sender(&self, sender: &Address) -> Vec<Transaction> {
        if let Some(sender_txs) = self.by_sender.get(sender) {
            sender_txs.values()
                .filter_map(|hash| self.transactions.get(hash))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Remove expired transactions
    pub fn remove_expired(&mut self) -> usize {
        let mut expired_hashes = Vec::new();

        for (hash, tx) in &self.transactions {
            if tx.is_expired(self.config.expiry_time) {
                expired_hashes.push(*hash);
            }
        }

        let count = expired_hashes.len();
        for hash in expired_hashes {
            self.remove_transaction(&hash);
        }

        if count > 0 {
            println!("🕒 Removed {} expired transactions", count);
        }

        count
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Clear all transactions
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.by_sender.clear();
        self.by_gas_price.clear();
        self.stats.current_size = 0;
        println!("🧹 Cleared transaction pool");
    }

    /// Update average gas price
    fn update_avg_gas_price(&mut self) {
        if self.transactions.is_empty() {
            self.stats.avg_gas_price = 0;
        } else {
            let total_gas_price: u64 = self.transactions.values().map(|tx| tx.gas_price).sum();
            self.stats.avg_gas_price = total_gas_price / self.transactions.len() as u64;
        }
    }

    /// Get transaction by hash
    pub fn get_transaction(&self, hash: &Hash) -> Option<&Transaction> {
        self.transactions.get(hash)
    }

    /// Check if transaction exists
    pub fn contains(&self, hash: &Hash) -> bool {
        self.transactions.contains_key(hash)
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.transactions.len()
    }
}

impl FeeCalculator {
    /// Create new fee calculator
    pub fn new() -> Self {
        Self {
            base_fee: 1000, // 1000 smallest units base fee
            data_fee_per_byte: 10, // 10 units per byte
            congestion_multiplier: 1.0,
        }
    }

    /// Calculate recommended fee for transaction
    pub fn calculate_fee(&self, tx: &Transaction, pool_size: usize, max_pool_size: usize) -> u64 {
        // Base fee
        let mut fee = self.base_fee;

        // Data fee
        fee += self.data_fee_per_byte * tx.data.len() as u64;

        // Gas fee
        fee += tx.gas_limit * tx.gas_price;

        // Congestion multiplier
        let congestion_ratio = pool_size as f64 / max_pool_size as f64;
        let congestion_multiplier = 1.0 + (congestion_ratio * 2.0); // Up to 3x during congestion
        
        fee = (fee as f64 * congestion_multiplier) as u64;

        fee
    }

    /// Get recommended gas price based on network conditions
    pub fn recommend_gas_price(&self, pool_stats: &PoolStats) -> u64 {
        let base_gas_price = 1_000_000; // 1 Gwei equivalent
        
        // Adjust based on average pool gas price
        if pool_stats.avg_gas_price > 0 {
            std::cmp::max(base_gas_price, pool_stats.avg_gas_price)
        } else {
            base_gas_price
        }
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_pool_size: 10000,
            max_per_account: 100,
            min_gas_price: 1_000_000, // 1 Gwei
            max_data_size: 1024 * 1024, // 1MB
            expiry_time: 3600, // 1 hour
        }
    }
}

impl Default for TransactionType {
    fn default() -> Self {
        TransactionType::Transfer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        let from = Address::from_bytes([1u8; 20]).unwrap();
        let to = Address::from_bytes([2u8; 20]).unwrap();
        
        let tx = Transaction::new(
            from,
            to,
            1000,
            100,
            21000,
            1_000_000,
            0,
            Vec::new(),
            TransactionType::Transfer,
        );

        assert_eq!(tx.from, from);
        assert_eq!(tx.to, to);
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 100);
        assert!(tx.validate_basic());
    }

    #[test]
    fn test_transaction_pool() {
        let mut pool = TransactionPool::new(PoolConfig::default());
        let from = Address::from_bytes([1u8; 20]).unwrap();
        let to = Address::from_bytes([2u8; 20]).unwrap();
        
        let tx = Transaction::new(
            from,
            to,
            1000,
            21_000_000_000, // gas_limit * gas_price
            21000,
            1_000_000,
            0,
            Vec::new(),
            TransactionType::Transfer,
        );

        // Add transaction
        assert!(pool.add_transaction(tx.clone()).is_ok());
        assert_eq!(pool.size(), 1);

        // Get transaction
        assert!(pool.get_transaction(&tx.hash).is_some());

        // Remove transaction
        assert!(pool.remove_transaction(&tx.hash).is_some());
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_fee_calculator() {
        let fee_calc = FeeCalculator::new();
        let from = Address::from_bytes([1u8; 20]).unwrap();
        let to = Address::from_bytes([2u8; 20]).unwrap();
        
        let tx = Transaction::new(
            from,
            to,
            1000,
            100,
            21000,
            1_000_000,
            0,
            b"test data".to_vec(),
            TransactionType::Transfer,
        );

        let fee = fee_calc.calculate_fee(&tx, 100, 1000);
        assert!(fee > 0);
    }
} 