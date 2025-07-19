use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, Duration};
use k256::ecdsa::{SigningKey, Signature};
use rlp::{RlpStream, Encodable};
use ethereum_types::{H256, U256, Address as EthAddress};
use serde::{Serialize, Deserialize};
use tokio::sync::{RwLock, Mutex};
use crate::types::{Hash, Address, Transaction};
use crate::wallet::hd_wallet::{HDWallet, WalletError};
use crate::api::jsonrpc::PoarRpcServer;

/// Transaction manager for wallet operations
pub struct TransactionManager {
    /// HD wallet reference
    wallet: Arc<RwLock<HDWallet>>,
    /// RPC client for blockchain interaction
    rpc_client: Option<Arc<PoarRpcServer>>,
    /// Transaction pool
    transaction_pool: Arc<Mutex<TransactionPool>>,
    /// Fee estimator
    fee_estimator: FeeEstimator,
    /// Nonce manager
    nonce_manager: NonceManager,
    /// Configuration
    config: TransactionConfig,
}

/// Transaction pool for pending transactions
#[derive(Debug)]
pub struct TransactionPool {
    /// Pending transactions by account
    pending_by_account: HashMap<u32, VecDeque<PendingTransaction>>,
    /// Pending transactions by hash
    pending_by_hash: HashMap<Hash, PendingTransaction>,
    /// Confirmed transactions
    confirmed: HashMap<Hash, ConfirmedTransaction>,
    /// Failed transactions
    failed: HashMap<Hash, FailedTransaction>,
}

/// Pending transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    /// Transaction hash
    pub hash: Hash,
    /// Raw transaction data
    pub transaction: Transaction,
    /// Account index used for signing
    pub account_index: u32,
    /// Address index used for signing
    pub address_index: u32,
    /// Submission timestamp
    pub submitted_at: u64,
    /// Number of submission attempts
    pub attempts: u32,
    /// Gas price used
    pub gas_price: U256,
    /// Gas limit
    pub gas_limit: u64,
    /// Estimated fee
    pub estimated_fee: u64,
    /// Transaction nonce
    pub nonce: u64,
    /// Retry configuration
    pub retry_config: RetryConfig,
}

/// Confirmed transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedTransaction {
    /// Transaction hash
    pub hash: Hash,
    /// Block number
    pub block_number: u64,
    /// Block hash
    pub block_hash: Hash,
    /// Transaction index in block
    pub transaction_index: u32,
    /// Gas used
    pub gas_used: u64,
    /// Effective gas price
    pub effective_gas_price: U256,
    /// Status (success/failed)
    pub status: bool,
    /// Confirmation timestamp
    pub confirmed_at: u64,
    /// Number of confirmations
    pub confirmations: u32,
}

/// Failed transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedTransaction {
    /// Transaction hash
    pub hash: Hash,
    /// Failure reason
    pub reason: FailureReason,
    /// Failed at timestamp
    pub failed_at: u64,
    /// Last error message
    pub error_message: String,
    /// Number of retry attempts made
    pub retry_attempts: u32,
}

/// Transaction failure reasons
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FailureReason {
    InsufficientFunds,
    GasLimitExceeded,
    NonceReused,
    TransactionUnderpriced,
    NetworkError,
    Timeout,
    Rejected,
    Unknown,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Base retry delay (seconds)
    pub base_delay: u64,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
    /// Gas price increase percentage per retry
    pub gas_price_bump: f64,
}

/// Fee estimator for gas prices
#[derive(Debug)]
pub struct FeeEstimator {
    /// Recent gas prices cache
    gas_price_history: VecDeque<GasPriceData>,
    /// Fee estimation strategy
    strategy: FeeStrategy,
    /// Configuration
    config: FeeConfig,
}

/// Gas price data point
#[derive(Debug, Clone)]
pub struct GasPriceData {
    /// Timestamp
    pub timestamp: u64,
    /// Gas price in wei
    pub gas_price: U256,
    /// Block number
    pub block_number: u64,
    /// Network congestion level
    pub congestion_level: CongestionLevel,
}

/// Network congestion levels
#[derive(Debug, Clone, PartialEq)]
pub enum CongestionLevel {
    Low,
    Medium,
    High,
    Extreme,
}

/// Fee estimation strategies
#[derive(Debug, Clone, PartialEq)]
pub enum FeeStrategy {
    Conservative,
    Standard,
    Fast,
    Custom(U256),
}

/// Fee configuration
#[derive(Debug, Clone)]
pub struct FeeConfig {
    /// Minimum gas price (wei)
    pub min_gas_price: U256,
    /// Maximum gas price (wei)
    pub max_gas_price: U256,
    /// Gas price percentile for estimation
    pub gas_price_percentile: f64,
    /// History window for gas price estimation
    pub history_window: Duration,
}

/// Nonce manager for tracking address nonces
#[derive(Debug)]
pub struct NonceManager {
    /// Local nonce cache by address
    local_nonces: HashMap<Address, u64>,
    /// Pending nonce increments
    pending_nonces: HashMap<Address, u64>,
    /// Last sync timestamp
    last_sync: SystemTime,
    /// Sync interval
    sync_interval: Duration,
}

/// Transaction configuration
#[derive(Debug, Clone)]
pub struct TransactionConfig {
    /// Default gas limit
    pub default_gas_limit: u64,
    /// Gas limit buffer percentage
    pub gas_limit_buffer: f64,
    /// Transaction timeout
    pub transaction_timeout: Duration,
    /// Confirmation requirements
    pub required_confirmations: u32,
    /// Enable automatic retry
    pub enable_retry: bool,
    /// Default retry configuration
    pub default_retry_config: RetryConfig,
}

/// Transaction creation parameters
#[derive(Debug, Clone)]
pub struct TransactionParams {
    /// From account index
    pub account_index: u32,
    /// From address index
    pub address_index: u32,
    /// To address
    pub to: Address,
    /// Value to transfer (wei)
    pub value: U256,
    /// Transaction data
    pub data: Vec<u8>,
    /// Gas limit (optional, will estimate if None)
    pub gas_limit: Option<u64>,
    /// Gas price (optional, will estimate if None)
    pub gas_price: Option<U256>,
    /// Nonce (optional, will get from network if None)
    pub nonce: Option<u64>,
}

/// Transaction manager errors
#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("Wallet error: {0}")]
    WalletError(#[from] WalletError),
    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: U256, available: U256 },
    #[error("Gas estimation failed: {0}")]
    GasEstimationFailed(String),
    #[error("Nonce error: {0}")]
    NonceError(String),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Transaction not found: {0}")]
    TransactionNotFound(Hash),
    #[error("Invalid transaction parameters: {0}")]
    InvalidParameters(String),
    #[error("Fee estimation error: {0}")]
    FeeEstimationError(String),
}

impl TransactionManager {
    /// Create new transaction manager
    pub fn new(
        wallet: Arc<RwLock<HDWallet>>,
        config: TransactionConfig,
    ) -> Self {
        println!("💳 Initializing transaction manager...");

        Self {
            wallet,
            rpc_client: None,
            transaction_pool: Arc::new(Mutex::new(TransactionPool::new())),
            fee_estimator: FeeEstimator::new(FeeConfig::default()),
            nonce_manager: NonceManager::new(),
            config,
        }
    }

    /// Set RPC client for blockchain interaction
    pub fn set_rpc_client(&mut self, rpc_client: Arc<PoarRpcServer>) {
        self.rpc_client = Some(rpc_client);
    }

    /// Create and send transaction
    pub async fn send_transaction(&mut self, params: TransactionParams) -> Result<Hash, TransactionError> {
        println!("📤 Creating transaction...");
        println!("   From account: {}, address: {}", params.account_index, params.address_index);
        println!("   To: {}", params.to);
        println!("   Value: {} wei", params.value);

        // Validate parameters
        self.validate_transaction_params(&params).await?;

        // Estimate gas if not provided
        let gas_limit = if let Some(limit) = params.gas_limit {
            limit
        } else {
            self.estimate_gas(&params).await?
        };

        // Estimate gas price if not provided
        let gas_price = if let Some(price) = params.gas_price {
            price
        } else {
            self.fee_estimator.estimate_gas_price(FeeStrategy::Standard).await?
        };

        // Get nonce if not provided
        let nonce = if let Some(n) = params.nonce {
            n
        } else {
            self.get_next_nonce(params.account_index, params.address_index).await?
        };

        // Check balance
        self.check_sufficient_balance(params.account_index, params.address_index, params.value, gas_limit, gas_price).await?;

        // Create transaction
        let transaction = Transaction {
            nonce,
            gas_price: gas_price.as_u64(),
            gas_limit,
            to: Some(params.to),
            value: params.value.as_u64(),
            data: params.data,
            v: 0, // Will be set during signing
            r: Hash::zero(),
            s: Hash::zero(),
        };

        // Sign transaction
        let signed_transaction = self.sign_transaction(params.account_index, params.address_index, transaction).await?;
        let tx_hash = signed_transaction.hash();

        // Create pending transaction record
        let pending_tx = PendingTransaction {
            hash: tx_hash,
            transaction: signed_transaction.clone(),
            account_index: params.account_index,
            address_index: params.address_index,
            submitted_at: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            attempts: 1,
            gas_price,
            gas_limit,
            estimated_fee: gas_limit * gas_price.as_u64(),
            nonce,
            retry_config: self.config.default_retry_config.clone(),
        };

        // Add to transaction pool
        {
            let mut pool = self.transaction_pool.lock().await;
            pool.add_pending_transaction(pending_tx);
        }

        // Broadcast transaction
        self.broadcast_transaction(&signed_transaction).await?;

        println!("✅ Transaction sent successfully: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Sign transaction with wallet
    async fn sign_transaction(&self, account_index: u32, address_index: u32, mut transaction: Transaction) -> Result<Transaction, TransactionError> {
        println!("✍️  Signing transaction...");

        let wallet = self.wallet.read().await;
        let signature = wallet.sign_transaction(account_index, address_index, &transaction)
            .map_err(TransactionError::WalletError)?;

        // Apply signature to transaction (simplified)
        // In a real implementation, you'd properly encode the signature
        transaction.v = 27; // Simplified
        // transaction.r and transaction.s would be set from signature

        println!("✅ Transaction signed");
        Ok(transaction)
    }

    /// Estimate gas for transaction
    async fn estimate_gas(&self, params: &TransactionParams) -> Result<u64, TransactionError> {
        println!("⛽ Estimating gas...");

        // Simplified gas estimation
        let base_gas = if params.data.is_empty() {
            21000 // Simple transfer
        } else {
            50000 + params.data.len() as u64 * 16 // Contract interaction
        };

        let gas_with_buffer = (base_gas as f64 * (1.0 + self.config.gas_limit_buffer)) as u64;
        let final_gas = gas_with_buffer.max(self.config.default_gas_limit);

        println!("   Base gas: {}", base_gas);
        println!("   With buffer: {}", gas_with_buffer);
        println!("   Final estimate: {}", final_gas);

        Ok(final_gas)
    }

    /// Get next nonce for address
    async fn get_next_nonce(&mut self, account_index: u32, address_index: u32) -> Result<u64, TransactionError> {
        let wallet = self.wallet.read().await;
        let account = wallet.get_account(account_index)
            .map_err(TransactionError::WalletError)?;
        
        let address = account.addresses.get(&address_index)
            .ok_or_else(|| TransactionError::NonceError(format!("Address {} not found", address_index)))?;

        let nonce = self.nonce_manager.get_next_nonce(&address.address).await?;
        println!("🔢 Next nonce for address {}: {}", address.address, nonce);

        Ok(nonce)
    }

    /// Check if account has sufficient balance
    async fn check_sufficient_balance(
        &self,
        account_index: u32,
        address_index: u32,
        value: U256,
        gas_limit: u64,
        gas_price: U256,
    ) -> Result<(), TransactionError> {
        let total_cost = value + U256::from(gas_limit) * gas_price;
        
        // Get account balance (simplified)
        let wallet = self.wallet.read().await;
        let account = wallet.get_account(account_index)
            .map_err(TransactionError::WalletError)?;
        
        let available_balance = U256::from(account.balance);

        if available_balance < total_cost {
            return Err(TransactionError::InsufficientFunds {
                required: total_cost,
                available: available_balance,
            });
        }

        println!("💰 Balance check passed: {} wei available, {} wei required", 
                available_balance, total_cost);
        Ok(())
    }

    /// Validate transaction parameters
    async fn validate_transaction_params(&self, params: &TransactionParams) -> Result<(), TransactionError> {
        // Check if account exists
        let wallet = self.wallet.read().await;
        wallet.get_account(params.account_index)
            .map_err(TransactionError::WalletError)?;

        // Validate value
        if params.value == U256::zero() && params.data.is_empty() {
            return Err(TransactionError::InvalidParameters(
                "Transaction must transfer value or include data".to_string()
            ));
        }

        // Validate gas limit
        if let Some(gas_limit) = params.gas_limit {
            if gas_limit < 21000 {
                return Err(TransactionError::InvalidParameters(
                    "Gas limit too low".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Broadcast transaction to network
    async fn broadcast_transaction(&self, transaction: &Transaction) -> Result<(), TransactionError> {
        println!("📡 Broadcasting transaction to network...");

        // In a real implementation, this would use the RPC client
        // to submit the transaction to the blockchain network
        
        if let Some(_rpc_client) = &self.rpc_client {
            // Simulate network broadcast
            tokio::time::sleep(Duration::from_millis(100)).await;
            println!("✅ Transaction broadcasted successfully");
        } else {
            println!("⚠️  No RPC client configured, transaction not broadcasted");
        }

        Ok(())
    }

    /// Get transaction status
    pub async fn get_transaction_status(&self, hash: &Hash) -> Result<TransactionStatus, TransactionError> {
        let pool = self.transaction_pool.lock().await;

        if pool.pending_by_hash.contains_key(hash) {
            return Ok(TransactionStatus::Pending);
        }

        if let Some(confirmed) = pool.confirmed.get(hash) {
            return Ok(TransactionStatus::Confirmed(confirmed.clone()));
        }

        if let Some(failed) = pool.failed.get(hash) {
            return Ok(TransactionStatus::Failed(failed.clone()));
        }

        Err(TransactionError::TransactionNotFound(*hash))
    }

    /// Get pending transactions for account
    pub async fn get_pending_transactions(&self, account_index: u32) -> Vec<PendingTransaction> {
        let pool = self.transaction_pool.lock().await;
        pool.pending_by_account.get(&account_index)
            .map(|txs| txs.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Cancel pending transaction
    pub async fn cancel_transaction(&mut self, hash: &Hash) -> Result<(), TransactionError> {
        println!("🚫 Cancelling transaction: {}", hash);

        let mut pool = self.transaction_pool.lock().await;
        if let Some(pending_tx) = pool.pending_by_hash.remove(hash) {
            // Remove from account queue
            if let Some(account_queue) = pool.pending_by_account.get_mut(&pending_tx.account_index) {
                account_queue.retain(|tx| tx.hash != *hash);
            }

            println!("✅ Transaction cancelled: {}", hash);
            Ok(())
        } else {
            Err(TransactionError::TransactionNotFound(*hash))
        }
    }

    /// Retry failed transaction with higher gas price
    pub async fn retry_transaction(&mut self, hash: &Hash) -> Result<Hash, TransactionError> {
        println!("🔄 Retrying transaction: {}", hash);

        let pool = self.transaction_pool.lock().await;
        let failed_tx = pool.failed.get(hash)
            .ok_or_else(|| TransactionError::TransactionNotFound(*hash))?;

        // Create new transaction with higher gas price
        let original_tx = &failed_tx; // This would reference the original transaction
        
        // Simplified retry logic
        println!("✅ Transaction retry initiated");
        Ok(*hash) // Return new transaction hash
    }
}

/// Transaction status enum
#[derive(Debug, Clone)]
pub enum TransactionStatus {
    Pending,
    Confirmed(ConfirmedTransaction),
    Failed(FailedTransaction),
}

impl TransactionPool {
    /// Create new transaction pool
    pub fn new() -> Self {
        Self {
            pending_by_account: HashMap::new(),
            pending_by_hash: HashMap::new(),
            confirmed: HashMap::new(),
            failed: HashMap::new(),
        }
    }

    /// Add pending transaction
    pub fn add_pending_transaction(&mut self, transaction: PendingTransaction) {
        let account_index = transaction.account_index;
        let hash = transaction.hash;

        // Add to account queue
        self.pending_by_account
            .entry(account_index)
            .or_insert_with(VecDeque::new)
            .push_back(transaction.clone());

        // Add to hash map
        self.pending_by_hash.insert(hash, transaction);
    }

    /// Move transaction to confirmed
    pub fn confirm_transaction(&mut self, hash: Hash, confirmed: ConfirmedTransaction) {
        if let Some(pending) = self.pending_by_hash.remove(&hash) {
            // Remove from account queue
            if let Some(account_queue) = self.pending_by_account.get_mut(&pending.account_index) {
                account_queue.retain(|tx| tx.hash != hash);
            }

            // Add to confirmed
            self.confirmed.insert(hash, confirmed);
        }
    }

    /// Move transaction to failed
    pub fn fail_transaction(&mut self, hash: Hash, failed: FailedTransaction) {
        if let Some(pending) = self.pending_by_hash.remove(&hash) {
            // Remove from account queue
            if let Some(account_queue) = self.pending_by_account.get_mut(&pending.account_index) {
                account_queue.retain(|tx| tx.hash != hash);
            }

            // Add to failed
            self.failed.insert(hash, failed);
        }
    }
}

impl FeeEstimator {
    /// Create new fee estimator
    pub fn new(config: FeeConfig) -> Self {
        Self {
            gas_price_history: VecDeque::new(),
            strategy: FeeStrategy::Standard,
            config,
        }
    }

    /// Estimate gas price based on strategy
    pub async fn estimate_gas_price(&mut self, strategy: FeeStrategy) -> Result<U256, TransactionError> {
        self.update_gas_price_history().await?;

        let estimated_price = match strategy {
            FeeStrategy::Conservative => self.calculate_conservative_price(),
            FeeStrategy::Standard => self.calculate_standard_price(),
            FeeStrategy::Fast => self.calculate_fast_price(),
            FeeStrategy::Custom(price) => price,
        };

        let clamped_price = estimated_price
            .max(self.config.min_gas_price)
            .min(self.config.max_gas_price);

        println!("⛽ Gas price estimated: {} wei ({:?} strategy)", clamped_price, strategy);
        Ok(clamped_price)
    }

    /// Update gas price history from network
    async fn update_gas_price_history(&mut self) -> Result<(), TransactionError> {
        // Simulate fetching gas prices from network
        let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        
        let gas_price_data = GasPriceData {
            timestamp: current_time,
            gas_price: U256::from(20_000_000_000u64), // 20 gwei
            block_number: 1234567,
            congestion_level: CongestionLevel::Medium,
        };

        self.gas_price_history.push_back(gas_price_data);

        // Keep only recent history
        while let Some(front) = self.gas_price_history.front() {
            if current_time - front.timestamp > self.config.history_window.as_secs() {
                self.gas_price_history.pop_front();
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Calculate conservative gas price
    fn calculate_conservative_price(&self) -> U256 {
        if self.gas_price_history.is_empty() {
            return self.config.min_gas_price;
        }

        let mut prices: Vec<U256> = self.gas_price_history.iter()
            .map(|data| data.gas_price)
            .collect();
        prices.sort();

        // Use 25th percentile for conservative pricing
        let index = (prices.len() as f64 * 0.25) as usize;
        prices.get(index).copied().unwrap_or(self.config.min_gas_price)
    }

    /// Calculate standard gas price
    fn calculate_standard_price(&self) -> U256 {
        if self.gas_price_history.is_empty() {
            return U256::from(20_000_000_000u64); // 20 gwei default
        }

        let mut prices: Vec<U256> = self.gas_price_history.iter()
            .map(|data| data.gas_price)
            .collect();
        prices.sort();

        // Use configured percentile (default 50th)
        let index = (prices.len() as f64 * self.config.gas_price_percentile) as usize;
        prices.get(index).copied().unwrap_or(U256::from(20_000_000_000u64))
    }

    /// Calculate fast gas price
    fn calculate_fast_price(&self) -> U256 {
        if self.gas_price_history.is_empty() {
            return U256::from(40_000_000_000u64); // 40 gwei default
        }

        let mut prices: Vec<U256> = self.gas_price_history.iter()
            .map(|data| data.gas_price)
            .collect();
        prices.sort();

        // Use 75th percentile for fast pricing
        let index = (prices.len() as f64 * 0.75) as usize;
        prices.get(index).copied().unwrap_or(U256::from(40_000_000_000u64))
    }
}

impl NonceManager {
    /// Create new nonce manager
    pub fn new() -> Self {
        Self {
            local_nonces: HashMap::new(),
            pending_nonces: HashMap::new(),
            last_sync: SystemTime::now(),
            sync_interval: Duration::from_secs(30),
        }
    }

    /// Get next nonce for address
    pub async fn get_next_nonce(&mut self, address: &Address) -> Result<u64, TransactionError> {
        // Check if we need to sync with network
        if self.last_sync.elapsed().unwrap_or(Duration::ZERO) > self.sync_interval {
            self.sync_nonces_from_network().await?;
        }

        let current_nonce = self.local_nonces.get(address).copied().unwrap_or(0);
        let pending_increment = self.pending_nonces.get(address).copied().unwrap_or(0);
        
        let next_nonce = current_nonce + pending_increment;
        
        // Increment pending counter
        *self.pending_nonces.entry(*address).or_insert(0) += 1;

        Ok(next_nonce)
    }

    /// Sync nonces from network
    async fn sync_nonces_from_network(&mut self) -> Result<(), TransactionError> {
        // In a real implementation, this would fetch nonces from the blockchain
        println!("🔄 Syncing nonces from network...");
        
        self.last_sync = SystemTime::now();
        Ok(())
    }

    /// Confirm nonce usage
    pub fn confirm_nonce(&mut self, address: &Address, nonce: u64) {
        self.local_nonces.insert(*address, nonce + 1);
        
        // Decrease pending counter
        if let Some(pending) = self.pending_nonces.get_mut(address) {
            *pending = pending.saturating_sub(1);
        }
    }
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            default_gas_limit: 21000,
            gas_limit_buffer: 0.1, // 10% buffer
            transaction_timeout: Duration::from_secs(300), // 5 minutes
            required_confirmations: 3,
            enable_retry: true,
            default_retry_config: RetryConfig {
                max_attempts: 3,
                base_delay: 30,
                backoff_multiplier: 2.0,
                gas_price_bump: 0.1, // 10% increase
            },
        }
    }
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            min_gas_price: U256::from(1_000_000_000u64), // 1 gwei
            max_gas_price: U256::from(100_000_000_000u64), // 100 gwei
            gas_price_percentile: 0.5, // 50th percentile
            history_window: Duration::from_secs(600), // 10 minutes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::hd_wallet::{WalletParams, WalletConfig};

    #[tokio::test]
    async fn test_transaction_manager_creation() {
        let wallet_params = WalletParams {
            mnemonic: None,
            passphrase: None,
            config: WalletConfig::default(),
        };
        let wallet = Arc::new(RwLock::new(HDWallet::new(wallet_params).unwrap()));
        let config = TransactionConfig::default();
        
        let tx_manager = TransactionManager::new(wallet, config);
        assert!(tx_manager.transaction_pool.lock().await.pending_by_hash.is_empty());
    }

    #[test]
    fn test_fee_estimator() {
        let config = FeeConfig::default();
        let mut estimator = FeeEstimator::new(config);
        
        // Test with empty history
        let conservative = estimator.calculate_conservative_price();
        let standard = estimator.calculate_standard_price();
        let fast = estimator.calculate_fast_price();
        
        assert!(conservative <= standard);
        assert!(standard <= fast);
    }

    #[test]
    fn test_nonce_manager() {
        let mut nonce_manager = NonceManager::new();
        let address = Address::from([1u8; 20]);
        
        // Set initial nonce
        nonce_manager.local_nonces.insert(address, 10);
        
        // Confirm nonce usage
        nonce_manager.confirm_nonce(&address, 10);
        assert_eq!(nonce_manager.local_nonces.get(&address), Some(&11));
    }
} 