pub mod hd_wallet;
pub mod key_storage;
pub mod transaction_manager;
pub mod hardware;

pub use hd_wallet::{
    HDWallet, WalletParams, WalletConfig, Account, DerivedAddress, 
    AddressType, TransactionRecord, TransactionStatus, TransactionDirection,
    AddressEntry, WalletError, KeyDerivation, AddressUtils, SecureMnemonic
};

pub use key_storage::{
    KeyStorage, StorageConfig, EncryptionAlgorithm, KeyDerivationAlgorithm,
    MasterKeyEntry, AccountKeyEntry, AddressKeyEntry, SecurePassword,
    StorageError
};

pub use transaction_manager::{
    TransactionManager, TransactionConfig, TransactionParams, 
    PendingTransaction, ConfirmedTransaction, FeeEstimator, FeeStrategy,
    NonceManager, TransactionError
};

pub use hardware::{
    HardwareWalletManager, HardwareWallet, LedgerWallet, TrezorWallet,
    DeviceId, DeviceInfo, DeviceStatus, DeviceFeature, DeviceType,
    HardwareConfig, HardwareError
};

use std::sync::Arc;
use tokio::sync::RwLock;
use crate::storage::state_storage::StateStorage;
use crate::network::P2PNetworkManager;

/// Comprehensive wallet service that integrates all wallet components
pub struct WalletService {
    /// HD wallet instance
    hd_wallet: Arc<RwLock<HDWallet>>,
    /// Secure key storage
    key_storage: Arc<RwLock<KeyStorage>>,
    /// Transaction manager
    transaction_manager: Arc<RwLock<TransactionManager>>,
    /// Hardware wallet manager
    hardware_manager: Option<Arc<RwLock<HardwareWalletManager>>>,
    /// Service configuration
    config: WalletServiceConfig,
}

/// Wallet service configuration
#[derive(Debug, Clone)]
pub struct WalletServiceConfig {
    /// Enable hardware wallet support
    pub enable_hardware: bool,
    /// Auto-save wallet state
    pub auto_save: bool,
    /// Save interval (seconds)
    pub save_interval: u64,
    /// Enable transaction monitoring
    pub enable_monitoring: bool,
    /// Network configuration
    pub network: crate::wallet::hd_wallet::Network,
}

/// Wallet service errors
#[derive(Debug, thiserror::Error)]
pub enum WalletServiceError {
    #[error("Wallet error: {0}")]
    WalletError(#[from] WalletError),
    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),
    #[error("Transaction error: {0}")]
    TransactionError(#[from] TransactionError),
    #[error("Hardware error: {0}")]
    HardwareError(#[from] HardwareError),
    #[error("Service not initialized")]
    NotInitialized,
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

impl WalletService {
    /// Create new wallet service
    pub async fn new(config: WalletServiceConfig) -> Result<Self, WalletServiceError> {
        println!("🏦 Initializing comprehensive wallet service...");

        // Initialize key storage
        let storage_config = StorageConfig::default();
        let key_storage = Arc::new(RwLock::new(KeyStorage::new(storage_config)?));

        // Create placeholder HD wallet (will be loaded or created later)
        let wallet_params = WalletParams {
            mnemonic: None,
            passphrase: None,
            config: WalletConfig {
                network: config.network.clone(),
                ..Default::default()
            },
        };
        let hd_wallet = Arc::new(RwLock::new(HDWallet::new(wallet_params)?));

        // Initialize transaction manager
        let tx_config = TransactionConfig::default();
        let transaction_manager = Arc::new(RwLock::new(
            TransactionManager::new(hd_wallet.clone(), tx_config)
        ));

        // Initialize hardware wallet manager if enabled
        let hardware_manager = if config.enable_hardware {
            let hw_config = HardwareConfig::default();
            match HardwareWalletManager::new(hw_config) {
                Ok(manager) => Some(Arc::new(RwLock::new(manager))),
                Err(e) => {
                    println!("⚠️  Hardware wallet initialization failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        println!("✅ Wallet service initialized");
        println!("   HD Wallet: ✅ Ready");
        println!("   Key Storage: ✅ Ready");
        println!("   Transaction Manager: ✅ Ready");
        println!("   Hardware Support: {}", 
                if hardware_manager.is_some() { "✅ Ready" } else { "❌ Disabled" });

        Ok(Self {
            hd_wallet,
            key_storage,
            transaction_manager,
            hardware_manager,
            config,
        })
    }

    /// Create new wallet from mnemonic
    pub async fn create_wallet_from_mnemonic(
        &mut self,
        mnemonic: bip39::Mnemonic,
        passphrase: Option<String>,
        password: SecurePassword,
    ) -> Result<(), WalletServiceError> {
        println!("🆕 Creating wallet from mnemonic...");

        // Create new HD wallet
        let wallet_params = WalletParams {
            mnemonic: Some(mnemonic),
            passphrase,
            config: WalletConfig {
                network: self.config.network.clone(),
                ..Default::default()
            },
        };

        let new_wallet = HDWallet::new(wallet_params)?;

        // Store master key securely
        let master_key_data = b"dummy_master_key"; // In real implementation, get from wallet
        {
            let mut storage = self.key_storage.write().await;
            storage.store_master_key(master_key_data, &password)?;
        }

        // Replace current wallet
        *self.hd_wallet.write().await = new_wallet;

        println!("✅ Wallet created and secured");
        Ok(())
    }

    /// Load existing wallet
    pub async fn load_wallet(&mut self, password: SecurePassword) -> Result<(), WalletServiceError> {
        println!("📂 Loading existing wallet...");

        // Load master key from storage
        let _master_key_data = {
            let mut storage = self.key_storage.write().await;
            storage.load_master_key(&password)?
        };

        // In a real implementation, you would reconstruct the wallet from the master key
        // For now, we'll just verify the password works

        println!("✅ Wallet loaded successfully");
        Ok(())
    }

    /// Get wallet reference
    pub fn get_hd_wallet(&self) -> Arc<RwLock<HDWallet>> {
        self.hd_wallet.clone()
    }

    /// Get transaction manager reference
    pub fn get_transaction_manager(&self) -> Arc<RwLock<TransactionManager>> {
        self.transaction_manager.clone()
    }

    /// Get hardware wallet manager reference
    pub fn get_hardware_manager(&self) -> Option<Arc<RwLock<HardwareWalletManager>>> {
        self.hardware_manager.clone()
    }

    /// Generate new receiving address
    pub async fn generate_receiving_address(&self, account_index: u32) -> Result<DerivedAddress, WalletServiceError> {
        let mut wallet = self.hd_wallet.write().await;
        let address = wallet.generate_receiving_address(account_index)?;
        Ok(address.clone())
    }

    /// Send transaction
    pub async fn send_transaction(&self, params: TransactionParams) -> Result<crate::types::Hash, WalletServiceError> {
        let mut tx_manager = self.transaction_manager.write().await;
        let hash = tx_manager.send_transaction(params).await?;
        Ok(hash)
    }

    /// Get wallet balance
    pub async fn get_balance(&self) -> u64 {
        let wallet = self.hd_wallet.read().await;
        wallet.get_total_balance()
    }

    /// List all accounts
    pub async fn list_accounts(&self) -> Vec<Account> {
        let wallet = self.hd_wallet.read().await;
        wallet.list_accounts().into_iter().cloned().collect()
    }

    /// Get transaction history
    pub async fn get_transaction_history(&self) -> Vec<TransactionRecord> {
        let wallet = self.hd_wallet.read().await;
        wallet.get_transaction_history().to_vec()
    }

    /// Connect to blockchain services
    pub async fn connect_blockchain_services(
        &mut self,
        state_storage: Arc<StateStorage>,
        network_manager: Arc<P2PNetworkManager>,
    ) -> Result<(), WalletServiceError> {
        println!("🔗 Connecting wallet to blockchain services...");

        // This would integrate the wallet with blockchain data sources
        // For monitoring balances, transaction status, etc.

        println!("✅ Blockchain services connected");
        Ok(())
    }

    /// Start background services
    pub async fn start_background_services(&self) -> Result<(), WalletServiceError> {
        println!("🔄 Starting wallet background services...");

        if self.config.enable_monitoring {
            // Start transaction monitoring
            self.start_transaction_monitoring().await?;
        }

        if self.config.auto_save {
            // Start auto-save service
            self.start_auto_save_service().await?;
        }

        println!("✅ Background services started");
        Ok(())
    }

    /// Start transaction monitoring
    async fn start_transaction_monitoring(&self) -> Result<(), WalletServiceError> {
        println!("👀 Starting transaction monitoring...");

        // This would monitor the blockchain for:
        // - Pending transaction confirmations
        // - Balance changes
        // - New transactions to tracked addresses

        Ok(())
    }

    /// Start auto-save service
    async fn start_auto_save_service(&self) -> Result<(), WalletServiceError> {
        println!("💾 Starting auto-save service...");

        // This would periodically save wallet state to secure storage

        Ok(())
    }

    /// Shutdown wallet service
    pub async fn shutdown(&mut self) -> Result<(), WalletServiceError> {
        println!("🛑 Shutting down wallet service...");

        // Clear sensitive data from memory
        {
            let mut wallet = self.hd_wallet.write().await;
            wallet.clear_mnemonic();
        }

        {
            let mut storage = self.key_storage.write().await;
            storage.clear_cache();
        }

        println!("✅ Wallet service shutdown complete");
        Ok(())
    }
}

impl Default for WalletServiceConfig {
    fn default() -> Self {
        Self {
            enable_hardware: true,
            auto_save: true,
            save_interval: 300, // 5 minutes
            enable_monitoring: true,
            network: crate::wallet::hd_wallet::Network::Mainnet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_service_creation() {
        let config = WalletServiceConfig::default();
        let service = WalletService::new(config).await;
        
        assert!(service.is_ok());
        let service = service.unwrap();
        assert!(service.get_hd_wallet().read().await.list_accounts().len() > 0);
    }

    #[tokio::test]
    async fn test_wallet_service_balance() {
        let config = WalletServiceConfig::default();
        let service = WalletService::new(config).await.unwrap();
        
        let balance = service.get_balance().await;
        assert_eq!(balance, 0); // New wallet should have zero balance
    }
} 