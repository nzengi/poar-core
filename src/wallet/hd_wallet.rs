use std::collections::HashMap;
use std::fmt;
use bip32::{ExtendedPrivateKey, ExtendedPublicKey, DerivationPath, ChildNumber};
use bip39::{Mnemonic, Language, Seed};
use k256::{ecdsa::{SigningKey, VerifyingKey, Signature}, elliptic_curve::SecretKey};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::OsRng;
use crate::types::{Hash, Address, Transaction};
use crate::crypto::falcon::{FalconSignatureManager, FalconConfig, FalconKeyPair};
use crate::types::signature::SignatureKind;
use crate::crypto::xmss::{XMSS, XMSSKeyPair, XMSSConfig, XMSSSignature};
use sha3::{Keccak256, Digest};
use crate::crypto::hash_based_multi_sig::{AggregatedSignature, aggregate_signatures, verify_aggregated_signature};

/// HD Wallet implementing BIP32/44/39 standards
#[derive(Debug)]
pub struct HDWallet {
    /// Master extended private key
    master_key: ExtendedPrivateKey<k256::Secp256k1>,
    /// Mnemonic phrase (optional, can be cleared for security)
    mnemonic: Option<Mnemonic>,
    /// Wallet configuration
    config: WalletConfig,
    /// Derived accounts cache
    accounts: HashMap<u32, Account>,
    /// Address book for external addresses
    address_book: HashMap<Address, AddressEntry>,
    /// Transaction history
    transaction_history: Vec<TransactionRecord>,
    /// Falcon keypairs (index -> keypair)
    pub falcon_keypairs: HashMap<u32, FalconKeyPair>,
    /// XMSS keypairs (index -> keypair)
    pub xmss_keypairs: HashMap<u32, XMSSKeyPair>,
}

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// BIP44 coin type (default: 60 for Ethereum)
    pub coin_type: u32,
    /// Network (mainnet/testnet)
    pub network: Network,
    /// Default account index
    pub default_account: u32,
    /// Address gap limit for scanning
    pub gap_limit: u32,
    /// Enable watch-only mode
    pub watch_only: bool,
}

/// Network type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
    Development,
}

/// Account derived from HD wallet
#[derive(Debug, Clone)]
pub struct Account {
    /// Account index
    pub index: u32,
    /// Account extended private key
    extended_private_key: ExtendedPrivateKey<k256::Secp256k1>,
    /// Account extended public key
    pub extended_public_key: ExtendedPublicKey<k256::Secp256k1>,
    /// Account name/label
    pub name: String,
    /// Derived addresses cache
    addresses: HashMap<u32, DerivedAddress>,
    /// Next address index to use
    next_address_index: u32,
    /// Account balance
    pub balance: u64,
}

/// Derived address from account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedAddress {
    /// Address index in derivation path
    pub index: u32,
    /// Ethereum address
    pub address: Address,
    /// Public key
    pub public_key: VerifyingKey,
    /// Derivation path
    pub path: DerivationPath,
    /// Address label
    pub label: Option<String>,
    /// Address balance
    pub balance: u64,
    /// Transaction count
    pub nonce: u64,
    /// Address type (receiving/change)
    pub address_type: AddressType,
}

/// Address type in HD derivation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AddressType {
    /// Receiving address (external chain)
    Receiving,
    /// Change address (internal chain)
    Change,
}

/// Address book entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    /// Address
    pub address: Address,
    /// Entry name/label
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Is this a contract address
    pub is_contract: bool,
    /// Creation timestamp
    pub created_at: u64,
}

/// Transaction record for history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Transaction hash
    pub hash: Hash,
    /// Transaction data
    pub transaction: Transaction,
    /// Block number (None if pending)
    pub block_number: Option<u64>,
    /// Timestamp
    pub timestamp: u64,
    /// Transaction status
    pub status: TransactionStatus,
    /// Gas used
    pub gas_used: Option<u64>,
    /// Transaction fee paid
    pub fee: u64,
    /// Associated account index
    pub account_index: Option<u32>,
    /// Associated address index
    pub address_index: Option<u32>,
    /// Transaction direction
    pub direction: TransactionDirection,
    /// Notes/memo
    pub notes: Option<String>,
}

/// Transaction status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
    Dropped,
}

/// Transaction direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionDirection {
    Incoming,
    Outgoing,
    Internal,
}

/// Wallet creation parameters
#[derive(Debug, Clone)]
pub struct WalletParams {
    /// Use existing mnemonic (None to generate new)
    pub mnemonic: Option<Mnemonic>,
    /// Mnemonic passphrase
    pub passphrase: Option<String>,
    /// Wallet configuration
    pub config: WalletConfig,
}

/// Secure mnemonic that zeros memory on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureMnemonic {
    words: String,
}

/// Key derivation utilities
pub struct KeyDerivation;

/// Address utilities
pub struct AddressUtils;

/// Wallet errors
#[derive(Debug)]
pub enum WalletError {
    InvalidMnemonic(String),
    DerivationError(String),
    AccountNotFound(u32),
    AddressNotFound(u32),
    InsufficientFunds { required: u64, available: u64 },
    InvalidSignature,
    EncryptionError(String),
    StorageError(String),
    HardwareWalletError(String),
}

impl HDWallet {
    /// Create a new HD wallet
    pub fn new(params: WalletParams) -> Result<Self, WalletError> {
        println!("🔐 Creating new HD wallet...");

        // Generate or use existing mnemonic
        let mnemonic = match params.mnemonic {
            Some(m) => m,
            None => {
                println!("   Generating new mnemonic phrase...");
                Mnemonic::generate_in(Language::English, 24)
                    .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?
            }
        };

        println!("   Mnemonic generated: {} words", mnemonic.word_count());

        // Generate seed from mnemonic
        let passphrase = params.passphrase.as_deref().unwrap_or("");
        let seed = bip39::Seed::new(&mnemonic, passphrase);

        // Derive master key
        let master_key = ExtendedPrivateKey::new(seed.as_bytes())
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;

        println!("   Master key derived successfully");

        let mut wallet = Self {
            master_key,
            mnemonic: Some(mnemonic),
            config: params.config,
            accounts: HashMap::new(),
            address_book: HashMap::new(),
            transaction_history: Vec::new(),
            falcon_keypairs: HashMap::new(),
            xmss_keypairs: HashMap::new(),
        };

        // Create default account
        wallet.create_account(0, "Default Account".to_string())?;

        println!("✅ HD wallet created successfully");
        Ok(wallet)
    }

    /// Create a new account
    pub fn create_account(&mut self, index: u32, name: String) -> Result<&Account, WalletError> {
        println!("👤 Creating account {} with name '{}'", index, name);

        // BIP44 derivation path: m/44'/coin_type'/account'/0/0
        let derivation_path = format!("m/44'/{}'/{}'", self.config.coin_type, index);
        let path: DerivationPath = derivation_path.parse()
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;

        // Derive account extended key
        let account_key = self.master_key.derive_priv(&path)
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;

        let account_public_key = ExtendedPublicKey::from_private_key(&account_key);

        let account = Account {
            index,
            extended_private_key: account_key,
            extended_public_key: account_public_key,
            name,
            addresses: HashMap::new(),
            next_address_index: 0,
            balance: 0,
        };

        self.accounts.insert(index, account);
        println!("✅ Account {} created successfully", index);

        Ok(self.accounts.get(&index).unwrap())
    }

    /// Get account by index
    pub fn get_account(&self, index: u32) -> Result<&Account, WalletError> {
        self.accounts.get(&index)
            .ok_or(WalletError::AccountNotFound(index))
    }

    /// Get mutable account by index
    pub fn get_account_mut(&mut self, index: u32) -> Result<&mut Account, WalletError> {
        self.accounts.get_mut(&index)
            .ok_or(WalletError::AccountNotFound(index))
    }

    /// List all accounts
    pub fn list_accounts(&self) -> Vec<&Account> {
        self.accounts.values().collect()
    }

    /// Generate new receiving address for account
    pub fn generate_receiving_address(&mut self, account_index: u32) -> Result<&DerivedAddress, WalletError> {
        let account = self.get_account_mut(account_index)?;
        let address_index = account.next_address_index;

        let derived_address = KeyDerivation::derive_address(
            &account.extended_private_key,
            AddressType::Receiving,
            address_index,
        )?;

        account.addresses.insert(address_index, derived_address);
        account.next_address_index += 1;

        println!("📍 Generated new receiving address: {} (index: {})", 
                account.addresses.get(&address_index).unwrap().address, address_index);

        Ok(account.addresses.get(&address_index).unwrap())
    }

    /// Generate change address for account
    pub fn generate_change_address(&mut self, account_index: u32) -> Result<&DerivedAddress, WalletError> {
        let account = self.get_account_mut(account_index)?;
        let address_index = account.next_address_index;

        let derived_address = KeyDerivation::derive_address(
            &account.extended_private_key,
            AddressType::Change,
            address_index,
        )?;

        account.addresses.insert(address_index, derived_address);
        account.next_address_index += 1;

        println!("📍 Generated new change address: {} (index: {})", 
                account.addresses.get(&address_index).unwrap().address, address_index);

        Ok(account.addresses.get(&address_index).unwrap())
    }

    /// Get all addresses for account
    pub fn get_addresses(&self, account_index: u32) -> Result<Vec<&DerivedAddress>, WalletError> {
        let account = self.get_account(account_index)?;
        Ok(account.addresses.values().collect())
    }

    /// Generate Falcon keypair for account (returns index)
    pub fn generate_falcon_keypair(&mut self, index: u32) -> u32 {
        let mut manager = FalconSignatureManager::new(FalconConfig::default());
        let keypair = manager.generate_key_pair();
        self.falcon_keypairs.insert(index, keypair);
        index
    }

    /// Get Falcon public key for index
    pub fn get_falcon_public_key(&self, index: u32) -> Option<&Vec<u8>> {
        self.falcon_keypairs.get(&index).map(|kp| &kp.public_key)
    }

    /// Sign transaction with specified address or Falcon keypair
    pub fn sign_transaction_with_kind(&self, account_index: u32, address_index: u32, transaction: &Transaction, kind: SignatureKind) -> Result<crate::types::Signature, WalletError> {
        match kind {
            SignatureKind::Ed25519 => {
                let account = self.get_account(account_index)?;
                let address = account.addresses.get(&address_index)
                    .ok_or(WalletError::AddressNotFound(address_index))?;
                let private_key = KeyDerivation::derive_private_key(
                    &account.extended_private_key,
                    address.address_type.clone(),
                    address_index,
                )?;
                let tx_hash = transaction.hash();
                let signing_key = k256::ecdsa::SigningKey::from(private_key);
                let signature = signing_key.sign(&tx_hash.0);
                Ok(crate::types::Signature::Ed25519(signature.to_bytes()))
            }
            SignatureKind::Falcon => {
                let keypair = self.falcon_keypairs.get(&address_index)
                    .ok_or(WalletError::AddressNotFound(address_index))?;
                let tx_hash = transaction.hash();
                let manager = FalconSignatureManager::new(FalconConfig::default());
                let sig = manager.sign(&tx_hash.0, &keypair.private_key)
                    .map_err(|_| WalletError::InvalidSignature)?;
                Ok(crate::types::Signature::Falcon(sig))
            }
            SignatureKind::XMSS => {
                let keypair = self.xmss_keypairs.get(&address_index)
                    .ok_or(WalletError::AddressNotFound(address_index))?;
                let tx_hash = transaction.hash();
                let sig = XMSS::sign(&tx_hash.0, &keypair.private_key);
                Ok(crate::types::Signature::XMSS(sig))
            }
        }
    }

    /// Add entry to address book
    pub fn add_address_book_entry(&mut self, entry: AddressEntry) {
        println!("📖 Adding address book entry: {} ({})", entry.address, entry.name);
        self.address_book.insert(entry.address, entry);
    }

    /// Get address book entry
    pub fn get_address_book_entry(&self, address: &Address) -> Option<&AddressEntry> {
        self.address_book.get(address)
    }

    /// Add transaction to history
    pub fn add_transaction_record(&mut self, record: TransactionRecord) {
        println!("📋 Adding transaction record: {} ({})", 
                record.hash, 
                match record.direction {
                    TransactionDirection::Incoming => "incoming",
                    TransactionDirection::Outgoing => "outgoing", 
                    TransactionDirection::Internal => "internal",
                });
        self.transaction_history.push(record);
    }

    /// Get transaction history
    pub fn get_transaction_history(&self) -> &[TransactionRecord] {
        &self.transaction_history
    }

    /// Get filtered transaction history
    pub fn get_filtered_transactions(&self, account_index: Option<u32>, status: Option<TransactionStatus>) -> Vec<&TransactionRecord> {
        self.transaction_history.iter()
            .filter(|record| {
                if let Some(acc_idx) = account_index {
                    if record.account_index != Some(acc_idx) {
                        return false;
                    }
                }
                if let Some(ref status) = status {
                    if &record.status != status {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Get wallet balance (sum of all accounts)
    pub fn get_total_balance(&self) -> u64 {
        self.accounts.values().map(|account| account.balance).sum()
    }

    /// Update account balance
    pub fn update_account_balance(&mut self, account_index: u32, balance: u64) -> Result<(), WalletError> {
        let account = self.get_account_mut(account_index)?;
        account.balance = balance;
        println!("💰 Updated account {} balance: {} wei", account_index, balance);
        Ok(())
    }

    /// Clear mnemonic from memory (for security)
    pub fn clear_mnemonic(&mut self) {
        if self.mnemonic.is_some() {
            self.mnemonic = None;
            println!("🔒 Mnemonic cleared from memory for security");
        }
    }

    /// Export account public key
    pub fn export_account_public_key(&self, account_index: u32) -> Result<ExtendedPublicKey<k256::Secp256k1>, WalletError> {
        let account = self.get_account(account_index)?;
        Ok(account.extended_public_key.clone())
    }

    /// Get mnemonic (if still in memory)
    pub fn get_mnemonic(&self) -> Option<&Mnemonic> {
        self.mnemonic.as_ref()
    }

    /// Get wallet configuration
    pub fn get_config(&self) -> &WalletConfig {
        &self.config
    }

    /// Create and store a new Falcon keypair, returning its index
    pub fn create_and_store_falcon_keypair(&mut self) -> u32 {
        let mut manager = FalconSignatureManager::new(FalconConfig::default());
        let keypair = manager.generate_key_pair();
        // Index olarak mevcut map'teki en büyük index + 1 kullanılır
        let new_index = if let Some(max) = self.falcon_keypairs.keys().max() {
            max + 1
        } else {
            0
        };
        self.falcon_keypairs.insert(new_index, keypair);
        new_index
    }

    /// Sign a transaction with a Falcon keypair by index
    pub fn sign_transaction_falcon(&self, falcon_index: u32, transaction: &Transaction) -> Result<crate::types::Signature, WalletError> {
        let keypair = self.falcon_keypairs.get(&falcon_index)
            .ok_or(WalletError::AddressNotFound(falcon_index))?;
        let tx_hash = transaction.hash();
        let manager = FalconSignatureManager::new(FalconConfig::default());
        let sig = manager.sign(&tx_hash.0, &keypair.private_key)
            .map_err(|_| WalletError::InvalidSignature)?;
        Ok(crate::types::Signature::Falcon(sig))
    }

    /// Create and store a new XMSS keypair, returning its index
    pub fn create_and_store_xmss_keypair(&mut self) -> u32 {
        let config = XMSSConfig::default();
        let keypair = XMSS::generate_keypair(&config);
        let new_index = if let Some(max) = self.xmss_keypairs.keys().max() {
            max + 1
        } else {
            0
        };
        self.xmss_keypairs.insert(new_index, keypair);
        new_index
    }

    /// Sign a transaction with an XMSS keypair by index
    pub fn sign_transaction_xmss(&self, xmss_index: u32, transaction: &Transaction) -> Result<crate::types::Signature, WalletError> {
        let keypair = self.xmss_keypairs.get(&xmss_index)
            .ok_or(WalletError::AddressNotFound(xmss_index))?;
        let tx_hash = transaction.hash();
        let sig = XMSS::sign(&tx_hash.0, &keypair.private_key);
        Ok(crate::types::Signature::XMSS(sig))
    }

    /// Aggregate XMSS signatures for a transaction
    pub fn aggregate_xmss_signatures(&self, indices: &[u32], transaction: &Transaction) -> crate::types::Signature {
        let tx_hash = transaction.hash();
        let mut sigs = Vec::new();
        for &i in indices {
            if let Some(kp) = self.xmss_keypairs.get(&i) {
                let sig = crate::crypto::xmss::XMSS::sign(&tx_hash.0, &kp.private_key);
                sigs.push(sig);
            }
        }
        let agg = aggregate_signatures(&sigs);
        crate::types::Signature::AggregatedHashBasedMultiSig(agg)
    }

    /// Verify an aggregated signature for a transaction
    pub fn verify_aggregated_signature(&self, agg_sig: &AggregatedSignature, transaction: &Transaction, public_keys: &[Vec<u8>]) -> bool {
        let tx_hash = transaction.hash();
        verify_aggregated_signature(&tx_hash.0, agg_sig, public_keys)
    }
}

impl KeyDerivation {
    /// Derive address from extended private key
    pub fn derive_address(
        account_key: &ExtendedPrivateKey<k256::Secp256k1>,
        address_type: AddressType,
        index: u32,
    ) -> Result<DerivedAddress, WalletError> {
        // BIP44 derivation: account/change/index
        let change_index = match address_type {
            AddressType::Receiving => 0,
            AddressType::Change => 1,
        };

        let path = DerivationPath::from([
            ChildNumber::new(change_index, false).unwrap(),
            ChildNumber::new(index, false).unwrap(),
        ]);

        let private_key = account_key.derive_priv(&path)
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;

        let public_key = private_key.public_key();
        let verifying_key = VerifyingKey::from(public_key);

        // Generate Ethereum address from public key
        let address = AddressUtils::public_key_to_address(&verifying_key);

        let full_path = format!("m/44'/60'/0'/{}/{}", change_index, index).parse()
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;

        Ok(DerivedAddress {
            index,
            address,
            public_key: verifying_key,
            path: full_path,
            label: None,
            balance: 0,
            nonce: 0,
            address_type,
        })
    }

    /// Derive private key for specific address
    pub fn derive_private_key(
        account_key: &ExtendedPrivateKey<k256::Secp256k1>,
        address_type: AddressType,
        index: u32,
    ) -> Result<SecretKey<k256::Secp256k1>, WalletError> {
        let change_index = match address_type {
            AddressType::Receiving => 0,
            AddressType::Change => 1,
        };

        let path = DerivationPath::from([
            ChildNumber::new(change_index, false).unwrap(),
            ChildNumber::new(index, false).unwrap(),
        ]);

        let private_key = account_key.derive_priv(&path)
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;

        Ok(private_key.private_key().clone())
    }
}

impl AddressUtils {
    /// Convert public key to Ethereum address
    pub fn public_key_to_address(public_key: &VerifyingKey) -> Address {
        // Get uncompressed public key bytes (remove 0x04 prefix)
        let public_key_bytes = public_key.to_encoded_point(false);
        let public_key_bytes = &public_key_bytes.as_bytes()[1..]; // Remove 0x04 prefix

        // Keccak256 hash of public key
        let mut hasher = Keccak256::new();
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();

        // Take last 20 bytes as address
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);

        Address::from(address_bytes)
    }

    /// Validate Ethereum address checksum
    pub fn validate_checksum(address: &str) -> bool {
        if !address.starts_with("0x") || address.len() != 42 {
            return false;
        }

        let address = &address[2..]; // Remove 0x prefix
        let mut hasher = Keccak256::new();
        hasher.update(address.to_lowercase().as_bytes());
        let hash = hasher.finalize();

        // Check EIP-55 checksum
        for (i, c) in address.chars().enumerate() {
            if c.is_alphabetic() {
                let should_be_uppercase = (hash[i / 2] >> (4 * (1 - i % 2))) & 0xf >= 8;
                if should_be_uppercase != c.is_uppercase() {
                    return false;
                }
            }
        }

        true
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            coin_type: 60, // Ethereum
            network: Network::Mainnet,
            default_account: 0,
            gap_limit: 20,
            watch_only: false,
        }
    }
}

impl fmt::Display for SecureMnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[PROTECTED MNEMONIC]")
    }
}

impl fmt::Debug for SecureMnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecureMnemonic {{ words: [REDACTED] }}")
    }
}

impl SecureMnemonic {
    /// Create secure mnemonic from string
    pub fn new(words: String) -> Self {
        Self { words }
    }

    /// Get mnemonic words (use carefully)
    pub fn reveal(&self) -> &str {
        &self.words
    }

    /// Parse as BIP39 mnemonic
    pub fn parse_mnemonic(&self) -> Result<Mnemonic, WalletError> {
        Mnemonic::parse(&self.words)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hd_wallet_creation() {
        let params = WalletParams {
            mnemonic: None,
            passphrase: None,
            config: WalletConfig::default(),
        };

        let wallet = HDWallet::new(params).unwrap();
        assert_eq!(wallet.accounts.len(), 1);
        assert!(wallet.get_account(0).is_ok());
    }

    #[test]
    fn test_address_generation() {
        let params = WalletParams {
            mnemonic: None,
            passphrase: None,
            config: WalletConfig::default(),
        };

        let mut wallet = HDWallet::new(params).unwrap();
        let address = wallet.generate_receiving_address(0).unwrap();
        
        assert_eq!(address.index, 0);
        assert_eq!(address.address_type, AddressType::Receiving);
        assert!(address.address.to_string().starts_with("0x"));
    }

    #[test]
    fn test_account_creation() {
        let params = WalletParams {
            mnemonic: None,
            passphrase: None,
            config: WalletConfig::default(),
        };

        let mut wallet = HDWallet::new(params).unwrap();
        wallet.create_account(1, "Test Account".to_string()).unwrap();
        
        let account = wallet.get_account(1).unwrap();
        assert_eq!(account.index, 1);
        assert_eq!(account.name, "Test Account");
    }

    #[test]
    fn test_address_checksum() {
        // Valid checksummed address
        let valid_address = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(AddressUtils::validate_checksum(valid_address));

        // Invalid checksum
        let invalid_address = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        assert!(!AddressUtils::validate_checksum(invalid_address));
    }

    #[test]
    fn test_mnemonic_security() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let secure_mnemonic = SecureMnemonic::new(words);
        
        // Should not reveal words in debug output
        let debug_output = format!("{:?}", secure_mnemonic);
        assert!(debug_output.contains("[REDACTED]"));
        
        // Should parse correctly
        assert!(secure_mnemonic.parse_mnemonic().is_ok());
    }
} 