 //! POAR Wallet System
//! 
//! This module provides a comprehensive wallet system designed specifically for POAR blockchain.
//! Features include:
//! - Multi-signature support (Ed25519, Falcon, XMSS, AggregatedHashBasedMultiSig)
//! - HD wallet with BIP32/44/39 standards
//! - ZK-Proof integration for wallet operations
//! - POAR token management with economic rules
//! - Hardware wallet support
//! - Secure encrypted storage
//! - Governance integration for validator voting

pub mod hd_wallet;
pub mod key_storage;
pub mod transaction_manager;
pub mod hardware;
pub mod governance;
pub mod zk_wallet;

use crate::types::{Transaction, Address, Signature, Hash, ZKProof};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fmt;

/// POAR Wallet Manager - Main wallet interface
pub struct POARWallet {
    /// HD wallet for key management
    hd_wallet: hd_wallet::HDWallet,
    /// Secure key storage
    key_storage: key_storage::KeyStorage,
    /// Transaction management
    transaction_manager: transaction_manager::TransactionManager,
    /// Hardware wallet support
    hardware_manager: hardware::HardwareWalletManager,
    /// Governance integration
    governance_wallet: governance::GovernanceWallet,
    /// ZK-Proof wallet operations
    zk_wallet: zk_wallet::ZKWallet,
    /// Wallet configuration
    config: WalletConfig,
}

/// Wallet configuration for POAR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Network type (mainnet/testnet/devnet)
    pub network: Network,
    /// Default signature type
    pub default_signature_type: SignatureType,
    /// Enable hardware wallet support
    pub enable_hardware: bool,
    /// Enable ZK-Proof operations
    pub enable_zk_proofs: bool,
    /// Governance participation enabled
    pub enable_governance: bool,
    /// Auto-stake validator rewards
    pub auto_stake_rewards: bool,
    /// Minimum stake for governance participation
    pub min_governance_stake: u64,
    /// Transaction fee strategy
    pub fee_strategy: FeeStrategy,
}

/// Network types for POAR
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

/// Supported signature types in POAR
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureType {
    Ed25519,
    Falcon,
    XMSS,
    AggregatedHashBasedMultiSig,
}

/// Fee calculation strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeeStrategy {
    /// Fixed fee in POAR
    Fixed(u64),
    /// Dynamic fee based on network conditions
    Dynamic,
    /// Gas-based fee calculation
    GasBased { gas_price: u64, gas_limit: u64 },
}

/// Wallet errors specific to POAR
#[derive(Debug)]
pub enum WalletError {
    // HD Wallet errors
    InvalidMnemonic(String),
    DerivationError(String),
    AccountNotFound(u32),
    AddressNotFound(u32),
    
    // Key storage errors
    EncryptionError(String),
    DecryptionError(String),
    StorageError(String),
    
    // Transaction errors
    InsufficientFunds { required: u64, available: u64 },
    InvalidTransaction(String),
    GasLimitExceeded(u64),
    NonceReused(u64),
    TransactionUnderpriced,
    
    // Hardware wallet errors
    HardwareDeviceNotFound(String),
    HardwareCommunicationError(String),
    HardwareSigningError(String),
    
    // ZK-Proof errors
    ZKProofGenerationError(String),
    ZKProofVerificationError(String),
    ZKCircuitError(String),
    
    // Governance errors
    InsufficientGovernanceStake { required: u64, available: u64 },
    InvalidProposal(String),
    VotingError(String),
    
    // Network errors
    NetworkError(String),
    Timeout(String),
    ConnectionError(String),
    
    // General errors
    ConfigurationError(String),
    Unknown(String),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::InvalidMnemonic(msg) => write!(f, "Invalid mnemonic: {}", msg),
            WalletError::DerivationError(msg) => write!(f, "Derivation error: {}", msg),
            WalletError::AccountNotFound(idx) => write!(f, "Account not found: {}", idx),
            WalletError::AddressNotFound(idx) => write!(f, "Address not found: {}", idx),
            WalletError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            WalletError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            WalletError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            WalletError::InsufficientFunds { required, available } => {
                write!(f, "Insufficient funds. Required: {}, Available: {}", required, available)
            }
            WalletError::InvalidTransaction(msg) => write!(f, "Invalid transaction: {}", msg),
            WalletError::GasLimitExceeded(limit) => write!(f, "Gas limit exceeded: {}", limit),
            WalletError::NonceReused(nonce) => write!(f, "Nonce reused: {}", nonce),
            WalletError::TransactionUnderpriced => write!(f, "Transaction underpriced"),
            WalletError::HardwareDeviceNotFound(msg) => write!(f, "Hardware device not found: {}", msg),
            WalletError::HardwareCommunicationError(msg) => write!(f, "Hardware communication error: {}", msg),
            WalletError::HardwareSigningError(msg) => write!(f, "Hardware signing error: {}", msg),
            WalletError::ZKProofGenerationError(msg) => write!(f, "ZK proof generation error: {}", msg),
            WalletError::ZKProofVerificationError(msg) => write!(f, "ZK proof verification error: {}", msg),
            WalletError::ZKCircuitError(msg) => write!(f, "ZK circuit error: {}", msg),
            WalletError::InsufficientGovernanceStake { required, available } => {
                write!(f, "Insufficient governance stake. Required: {}, Available: {}", required, available)
            }
            WalletError::InvalidProposal(msg) => write!(f, "Invalid proposal: {}", msg),
            WalletError::VotingError(msg) => write!(f, "Voting error: {}", msg),
            WalletError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            WalletError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            WalletError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            WalletError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            WalletError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for WalletError {}

// Implement From traits for error conversion
impl From<hd_wallet::HDWalletError> for WalletError {
    fn from(err: hd_wallet::HDWalletError) -> Self {
        match err {
            hd_wallet::HDWalletError::InvalidMnemonic(msg) => WalletError::InvalidMnemonic(msg),
            hd_wallet::HDWalletError::DerivationError(msg) => WalletError::DerivationError(msg),
            hd_wallet::HDWalletError::AccountNotFound(idx) => WalletError::AccountNotFound(idx),
            hd_wallet::HDWalletError::AddressNotFound(idx) => WalletError::AddressNotFound(idx),
            hd_wallet::HDWalletError::SignatureError(msg) => WalletError::InvalidTransaction(msg),
            hd_wallet::HDWalletError::KeyGenerationError(msg) => WalletError::ConfigurationError(msg),
            hd_wallet::HDWalletError::SerializationError(msg) => WalletError::Unknown(msg),
        }
    }
}

impl From<key_storage::KeyStorageError> for WalletError {
    fn from(err: key_storage::KeyStorageError) -> Self {
        match err {
            key_storage::KeyStorageError::EncryptionError(msg) => WalletError::EncryptionError(msg),
            key_storage::KeyStorageError::DecryptionError(msg) => WalletError::DecryptionError(msg),
            key_storage::KeyStorageError::StorageError(msg) => WalletError::StorageError(msg),
            key_storage::KeyStorageError::KeyDerivationError(msg) => WalletError::DerivationError(msg),
            key_storage::KeyStorageError::InvalidPassword(msg) => WalletError::ConfigurationError(msg),
            key_storage::KeyStorageError::KeyNotFound(msg) => WalletError::Unknown(msg),
            key_storage::KeyStorageError::HardwareError(msg) => WalletError::HardwareCommunicationError(msg),
            key_storage::KeyStorageError::RestoreError(msg) => WalletError::StorageError(msg),
            key_storage::KeyStorageError::Unknown(msg) => WalletError::Unknown(msg),
            key_storage::KeyStorageError::BackupError(msg) => WalletError::StorageError(msg),
        }
    }
}

impl From<zk_wallet::ZKWalletError> for WalletError {
    fn from(err: zk_wallet::ZKWalletError) -> Self {
        match err {
            zk_wallet::ZKWalletError::ProofGenerationError(msg) => WalletError::ZKProofGenerationError(msg),
            zk_wallet::ZKWalletError::ProofVerificationError(msg) => WalletError::ZKProofVerificationError(msg),
            zk_wallet::ZKWalletError::CircuitError(msg) => WalletError::ZKCircuitError(msg),
            zk_wallet::ZKWalletError::InvalidInput(msg) => WalletError::InvalidTransaction(msg),
            zk_wallet::ZKWalletError::InsufficientBalance(msg) => WalletError::InsufficientFunds { required: 0, available: 0 },
            zk_wallet::ZKWalletError::PrivacyError(msg) => WalletError::InvalidTransaction(msg),
            zk_wallet::ZKWalletError::NetworkError(msg) => WalletError::NetworkError(msg),
            zk_wallet::ZKWalletError::Unknown(msg) => WalletError::Unknown(msg),
        }
    }
}

impl From<hardware::HardwareWalletError> for WalletError {
    fn from(err: hardware::HardwareWalletError) -> Self {
        match err {
            hardware::HardwareWalletError::DeviceNotFound(msg) => WalletError::HardwareDeviceNotFound(msg),
            hardware::HardwareWalletError::CommunicationError(msg) => WalletError::HardwareCommunicationError(msg),
            hardware::HardwareWalletError::SigningError(msg) => WalletError::HardwareSigningError(msg),
            hardware::HardwareWalletError::ConnectionFailed(msg) => WalletError::HardwareCommunicationError(msg),
            hardware::HardwareWalletError::InvalidDerivationPath(msg) => WalletError::DerivationError(msg),
            hardware::HardwareWalletError::DeviceLocked(msg) => WalletError::HardwareDeviceNotFound(msg),
            hardware::HardwareWalletError::UnsupportedFeature(msg) => WalletError::ConfigurationError(msg),
            hardware::HardwareWalletError::Timeout(msg) => WalletError::Timeout(msg),
            hardware::HardwareWalletError::InvalidResponse(msg) => WalletError::HardwareCommunicationError(msg),
            hardware::HardwareWalletError::Unknown(msg) => WalletError::Unknown(msg),
        }
    }
}

impl From<governance::GovernanceError> for WalletError {
    fn from(err: governance::GovernanceError) -> Self {
        match err {
            governance::GovernanceError::InsufficientStake { required, available } => 
                WalletError::InsufficientGovernanceStake { required, available },
            governance::GovernanceError::InvalidProposal(msg) => WalletError::InvalidProposal(msg),
            governance::GovernanceError::ProposalNotFound(id) => WalletError::InvalidProposal(format!("Proposal not found: {}", id)),
            governance::GovernanceError::VotingPeriodEnded(id) => WalletError::InvalidProposal(format!("Voting period ended: {}", id)),
            governance::GovernanceError::AlreadyVoted(id) => WalletError::InvalidProposal(format!("Already voted: {}", id)),
            governance::GovernanceError::InvalidVote(msg) => WalletError::VotingError(msg),
            governance::GovernanceError::ExecutionFailed(msg) => WalletError::InvalidTransaction(msg),
            governance::GovernanceError::NetworkError(msg) => WalletError::NetworkError(msg),
            governance::GovernanceError::Unknown(msg) => WalletError::Unknown(msg),
        }
    }
}

impl POARWallet {
    /// Create a new POAR wallet
    pub fn new(config: WalletConfig) -> Result<Self, WalletError> {
        let (hd_wallet, _) = hd_wallet::HDWallet::new()?;
        let key_storage = key_storage::KeyStorage::new("poar_wallet".to_string(), "default_password")?;
        let transaction_manager = transaction_manager::TransactionManager::new();
        let hardware_manager = hardware::HardwareWalletManager::new();
        let governance_wallet = governance::GovernanceWallet::new();
        let zk_wallet = zk_wallet::ZKWallet::new()?;

        Ok(Self {
            hd_wallet,
            key_storage,
            transaction_manager,
            hardware_manager,
            governance_wallet,
            zk_wallet,
            config,
        })
    }

    /// Initialize wallet from mnemonic
    pub fn from_mnemonic(mnemonic: &str, passphrase: Option<&str>, config: WalletConfig) -> Result<Self, WalletError> {
        let mut wallet = Self::new(config)?;
        let (hd_wallet, _) = hd_wallet::HDWallet::from_mnemonic(mnemonic, passphrase)?;
        wallet.hd_wallet = hd_wallet;
        Ok(wallet)
    }

    /// Generate new wallet with random mnemonic
    pub fn generate(config: WalletConfig) -> Result<(Self, String), WalletError> {
        let (hd_wallet, mnemonic) = hd_wallet::HDWallet::generate()?;
        let key_storage = key_storage::KeyStorage::new("poar_wallet".to_string(), "default_password")?;
        let transaction_manager = transaction_manager::TransactionManager::new();
        let hardware_manager = hardware::HardwareWalletManager::new();
        let governance_wallet = governance::GovernanceWallet::new();
        let zk_wallet = zk_wallet::ZKWallet::new()?;

        let wallet = Self {
            hd_wallet,
            key_storage,
            transaction_manager,
            hardware_manager,
            governance_wallet,
            zk_wallet,
            config,
        };

        Ok((wallet, mnemonic))
    }

    /// Get wallet balance in POAR units
    pub fn get_balance_poar(&self) -> u64 {
        // This would query the blockchain for actual balance
        0 // Placeholder
    }

    /// Get wallet balance in ZERO units
    pub fn get_balance_zero(&self) -> u64 {
        // This would query the blockchain for actual balance
        0 // Placeholder
    }

    /// Get wallet balance in PROOF units
    pub fn get_balance_proof(&self) -> u64 {
        // This would query the blockchain for actual balance
        0 // Placeholder
    }

    /// Get wallet balance in VALID units
    pub fn get_balance_valid(&self) -> u64 {
        // This would query the blockchain for actual balance
        0 // Placeholder
    }

    /// Create and sign a POAR transaction
    pub fn create_transaction(
        &mut self,
        to: Address,
        amount: u64,
        signature_type: Option<SignatureType>,
    ) -> Result<Transaction, WalletError> {
        let sig_type = signature_type.unwrap_or(self.config.default_signature_type.clone());
        
        let transaction = Transaction {
            from: self.get_default_address()?,
            to,
            amount,
            gas_limit: 21000, // Default gas limit
            gas_price: 1, // Default gas price
            nonce: self.get_nonce()?,
            data: Vec::new(),
            signature: Signature::dummy(), // Will be signed below
            hash: Hash::zero(),
            fee: 0,
            timestamp: 0,
            tx_type: crate::types::transaction::TransactionType::Transfer,
        };

        let signed_transaction = self.sign_transaction(transaction, sig_type)?;
        Ok(signed_transaction)
    }

    /// Sign a transaction with specified signature type
    pub fn sign_transaction(&self, mut transaction: Transaction, signature_type: SignatureType) -> Result<Transaction, WalletError> {
        let tx_hash_bytes = transaction.hash.as_bytes();
        
        let signature = match signature_type {
            SignatureType::Ed25519 => self.hd_wallet.sign_ed25519(tx_hash_bytes)?,
            SignatureType::Falcon => self.hd_wallet.sign_falcon(tx_hash_bytes)?,
            SignatureType::XMSS => self.hd_wallet.sign_xmss(tx_hash_bytes)?,
            SignatureType::AggregatedHashBasedMultiSig => self.hd_wallet.sign_aggregated(tx_hash_bytes)?,
        };

        transaction.signature = signature;
        Ok(transaction)
    }

    /// Submit a transaction to the network
    pub fn submit_transaction(&mut self, transaction: Transaction) -> Result<Hash, WalletError> {
        let metadata = transaction_manager::TransactionMetadata::default();
        self.transaction_manager.submit_transaction(transaction, metadata).map_err(|e| WalletError::NetworkError(e.to_string()))
    }

    /// Generate ZK-Proof for transaction
    pub fn generate_zk_proof(&mut self, transaction: &Transaction) -> Result<ZKProof, WalletError> {
        let input = zk_wallet::TransactionProofInput {
            sender: self.get_default_address()?,
            recipient: transaction.to,
            amount: transaction.amount,
            balance_before: 0,
            balance_after: 0,
            nonce: transaction.nonce,
            fee: transaction.fee,
            timestamp: transaction.timestamp,
        };
        self.zk_wallet.generate_transaction_proof(transaction, input).map_err(|e| WalletError::ZKProofGenerationError(e.to_string()))
    }

    /// Verify ZK-Proof
    pub fn verify_zk_proof(&self, proof: &ZKProof) -> Result<bool, WalletError> {
        self.zk_wallet.verify_proof(proof).map_err(|e| WalletError::ZKProofVerificationError(e.to_string()))
    }

    /// Participate in governance voting
    pub fn vote_on_proposal(&mut self, proposal_id: u64, vote: bool) -> Result<(), WalletError> {
        let address = self.get_default_address()?;
        let vote_type = if vote { governance::VoteType::Yes } else { governance::VoteType::No };
        let stake = 1000; // Default stake amount
        self.governance_wallet.vote_on_proposal(proposal_id, address, vote_type, stake).map_err(|e| WalletError::VotingError(e.to_string()))
    }

    /// Submit a governance proposal
    pub fn submit_proposal(&mut self, proposal_type: governance::ProposalType, payload: Vec<u8>) -> Result<u64, WalletError> {
        let address = self.get_default_address()?;
        let description = "Proposal description".to_string();
        let stake = 1000; // Default stake amount
        let payload_string = String::from_utf8(payload).map_err(|e| WalletError::InvalidProposal(e.to_string()))?;
        self.governance_wallet.submit_proposal(address, proposal_type, description, payload_string, stake).map_err(|e| WalletError::InvalidProposal(e.to_string()))
    }

    /// Get governance participation status
    pub fn get_governance_status(&self) -> governance::GovernanceStatus {
        self.governance_wallet.get_status()
    }

    /// Connect hardware wallet
    pub fn connect_hardware_wallet(&mut self, device_id: &str) -> Result<(), WalletError> {
        let device_type = hardware::HardwareWalletType::LedgerNanoS;
        self.hardware_manager.connect_device(device_id, device_type).map_err(|e| WalletError::HardwareCommunicationError(e.to_string()))
    }

    /// Sign with hardware wallet
    pub fn sign_with_hardware(&self, device_id: &str, transaction: &Transaction) -> Result<Signature, WalletError> {
        let path = None; // Default derivation path
        self.hardware_manager.sign_transaction(device_id, transaction, path).map_err(|e| WalletError::HardwareSigningError(e.to_string()))
    }

    /// Export wallet data
    pub fn export(&self) -> Result<String, WalletError> {
        let wallet_data = WalletExport {
            hd_wallet: self.hd_wallet.export()?,
            config: self.config.clone(),
            governance_status: self.governance_wallet.get_status(),
        };
        
        serde_json::to_string_pretty(&wallet_data)
            .map_err(|e| WalletError::StorageError(e.to_string()))
    }

    /// Import wallet data
    pub fn import(json: &str) -> Result<Self, WalletError> {
        let wallet_data: WalletExport = serde_json::from_str(json)
            .map_err(|e| WalletError::StorageError(e.to_string()))?;
        
        let hd_wallet = hd_wallet::HDWallet::import(&wallet_data.hd_wallet)?;
        let key_storage = key_storage::KeyStorage::new("poar_wallet".to_string(), "default_password")?;
        let transaction_manager = transaction_manager::TransactionManager::new();
        let hardware_manager = hardware::HardwareWalletManager::new();
        let governance_wallet = governance::GovernanceWallet::new();
        let zk_wallet = zk_wallet::ZKWallet::new()?;

        Ok(Self {
            hd_wallet,
            key_storage,
            transaction_manager,
            hardware_manager,
            governance_wallet,
            zk_wallet,
            config: wallet_data.config,
        })
    }

    // Helper methods
    fn get_default_address(&mut self) -> Result<Address, WalletError> {
        self.hd_wallet.get_address(0, 0, 0).map_err(|e| WalletError::AddressNotFound(0))
    }

    fn get_nonce(&self) -> Result<u64, WalletError> {
        // This would query the blockchain for the current nonce
        Ok(0) // Placeholder
    }
}

/// Wallet export data structure
#[derive(Debug, Serialize, Deserialize)]
struct WalletExport {
    hd_wallet: String,
    config: WalletConfig,
    governance_status: governance::GovernanceStatus,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            network: Network::Testnet,
            default_signature_type: SignatureType::Ed25519,
            enable_hardware: true,
            enable_zk_proofs: true,
            enable_governance: true,
            auto_stake_rewards: false,
            min_governance_stake: 50_000, // 50k POAR minimum stake
            fee_strategy: FeeStrategy::Dynamic,
        }
    }
}