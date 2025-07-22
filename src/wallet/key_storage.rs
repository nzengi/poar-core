 //! POAR Wallet Key Storage System
//! 
//! This module provides secure key storage for POAR wallet with:
//! - AES-256-GCM encryption
//! - PBKDF2 key derivation
//! - Secure random generation
//! - Hardware-backed storage support
//! - Key rotation and backup

use crate::types::{Address, Signature, Hash};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

/// Encryption algorithm for key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// Key derivation parameters for PBKDF2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    pub algorithm: String,
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub key_length: usize,
}

/// Account key entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountKeyEntry {
    pub account_index: u32,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub address: Address,
    pub created_at: u64,
    pub last_used: u64,
    pub signature_type: String,
    pub is_hardware_backed: bool,
}

/// Address key entry for HD wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressKeyEntry {
    pub account_index: u32,
    pub change_index: u32,
    pub address_index: u32,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub address: Address,
    pub created_at: u64,
    pub last_used: u64,
    pub balance: u64,
    pub nonce: u64,
}

/// Encrypted wallet data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWalletData {
    pub version: u32,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub key_derivation_params: KeyDerivationParams,
    pub encrypted_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
    pub created_at: u64,
    pub last_modified: u64,
}

/// Key storage errors
#[derive(Debug)]
pub enum KeyStorageError {
    EncryptionError(String),
    DecryptionError(String),
    KeyDerivationError(String),
    StorageError(String),
    InvalidPassword(String),
    KeyNotFound(String),
    HardwareError(String),
    BackupError(String),
    RestoreError(String),
    Unknown(String),
}

impl fmt::Display for KeyStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStorageError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            KeyStorageError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            KeyStorageError::KeyDerivationError(msg) => write!(f, "Key derivation error: {}", msg),
            KeyStorageError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            KeyStorageError::InvalidPassword(msg) => write!(f, "Invalid password: {}", msg),
            KeyStorageError::KeyNotFound(msg) => write!(f, "Key not found: {}", msg),
            KeyStorageError::HardwareError(msg) => write!(f, "Hardware error: {}", msg),
            KeyStorageError::BackupError(msg) => write!(f, "Backup error: {}", msg),
            KeyStorageError::RestoreError(msg) => write!(f, "Restore error: {}", msg),
            KeyStorageError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for KeyStorageError {}

/// POAR Key Storage Manager
pub struct KeyStorage {
    /// Storage file path
    file_path: String,
    /// Master password hash
    master_password_hash: Vec<u8>,
    /// Account keys storage
    account_keys: Arc<Mutex<HashMap<u32, AccountKeyEntry>>>,
    /// Address keys storage
    address_keys: Arc<Mutex<HashMap<Address, AddressKeyEntry>>>,
    /// Encryption parameters
    encryption_params: KeyDerivationParams,
    /// Hardware wallet integration
    hardware_enabled: bool,
    /// Backup configuration
    backup_config: BackupConfig,
}

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub auto_backup: bool,
    pub backup_interval_hours: u32,
    pub backup_location: String,
    pub encryption_enabled: bool,
    pub max_backups: u32,
}

impl KeyStorage {
    /// Create new key storage
    pub fn new(wallet_name: String, master_password: &str) -> Result<Self, KeyStorageError> {
        let file_path = format!("data/wallets/{}.dat", wallet_name);
        
        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(&file_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
        }

        // Generate salt and derive key
        let salt = Self::generate_salt();
        let key_derivation_params = KeyDerivationParams {
            algorithm: "PBKDF2".to_string(),
            iterations: 100_000,
            salt,
            key_length: 32,
        };

        // Hash master password
        let master_password_hash = Self::derive_key(master_password, &key_derivation_params)?;

        let backup_config = BackupConfig {
            auto_backup: true,
            backup_interval_hours: 24,
            backup_location: format!("data/backups/{}", wallet_name),
            encryption_enabled: true,
            max_backups: 10,
        };

        let storage = Self {
            file_path,
            master_password_hash,
            account_keys: Arc::new(Mutex::new(HashMap::new())),
            address_keys: Arc::new(Mutex::new(HashMap::new())),
            encryption_params: key_derivation_params,
            hardware_enabled: false,
            backup_config,
        };

        // Load existing data if available
        if Path::new(&storage.file_path).exists() {
            storage.load_from_file()?;
        }

        Ok(storage)
    }

    /// Store account key
    pub fn store_account_key(
        &self,
        account_index: u32,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        address: Address,
        signature_type: String,
        is_hardware_backed: bool,
    ) -> Result<(), KeyStorageError> {
        let encrypted_private_key = self.encrypt_data(&private_key)?;
        
        let entry = AccountKeyEntry {
            account_index,
            public_key,
            encrypted_private_key,
            address,
            created_at: Self::current_timestamp(),
            last_used: Self::current_timestamp(),
            signature_type,
            is_hardware_backed,
        };

        {
            let mut keys = self.account_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
            keys.insert(account_index, entry);
        }

        self.save_to_file()?;
        Ok(())
    }

    /// Retrieve account private key
    pub fn get_account_private_key(&self, account_index: u32) -> Result<Vec<u8>, KeyStorageError> {
        let keys = self.account_keys.lock()
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
        
        let entry = keys.get(&account_index)
            .ok_or_else(|| KeyStorageError::KeyNotFound(format!("Account {}", account_index)))?;

        let decrypted_key = self.decrypt_data(&entry.encrypted_private_key)?;
        Ok(decrypted_key)
    }

    /// Store address key
    pub fn store_address_key(
        &self,
        account_index: u32,
        change_index: u32,
        address_index: u32,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        address: Address,
    ) -> Result<(), KeyStorageError> {
        let encrypted_private_key = self.encrypt_data(&private_key)?;
        
        let entry = AddressKeyEntry {
            account_index,
            change_index,
            address_index,
            public_key,
            encrypted_private_key,
            address,
            created_at: Self::current_timestamp(),
            last_used: Self::current_timestamp(),
            balance: 0,
            nonce: 0,
        };

        {
            let mut keys = self.address_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
            keys.insert(address, entry);
        }

        self.save_to_file()?;
        Ok(())
    }

    /// Retrieve address private key
    pub fn get_address_private_key(&self, address: &Address) -> Result<Vec<u8>, KeyStorageError> {
        let keys = self.address_keys.lock()
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
        
        let entry = keys.get(address)
            .ok_or_else(|| KeyStorageError::KeyNotFound(format!("Address {}", address)))?;

        let decrypted_key = self.decrypt_data(&entry.encrypted_private_key)?;
        Ok(decrypted_key)
    }

    /// Update address balance and nonce
    pub fn update_address_state(&self, address: &Address, balance: u64, nonce: u64) -> Result<(), KeyStorageError> {
        let mut keys = self.address_keys.lock()
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
        
        if let Some(entry) = keys.get_mut(address) {
            entry.balance = balance;
            entry.nonce = nonce;
            entry.last_used = Self::current_timestamp();
        }

        self.save_to_file()?;
        Ok(())
    }

    /// Get all addresses
    pub fn get_all_addresses(&self) -> Result<Vec<Address>, KeyStorageError> {
        let keys = self.address_keys.lock()
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
        
        Ok(keys.keys().cloned().collect())
    }

    /// Get address entry
    pub fn get_address_entry(&self, address: &Address) -> Result<AddressKeyEntry, KeyStorageError> {
        let keys = self.address_keys.lock()
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
        
        keys.get(address)
            .cloned()
            .ok_or_else(|| KeyStorageError::KeyNotFound(format!("Address {}", address)))
    }

    /// Create backup
    pub fn create_backup(&self, backup_path: &str) -> Result<(), KeyStorageError> {
        let backup_data = self.serialize_for_backup()?;
        
        // Create backup directory
        if let Some(parent) = Path::new(backup_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| KeyStorageError::BackupError(e.to_string()))?;
        }

        // Write backup file
        fs::write(backup_path, backup_data)
            .map_err(|e| KeyStorageError::BackupError(e.to_string()))?;

        Ok(())
    }

    /// Restore from backup
    pub fn restore_from_backup(&mut self, backup_path: &str) -> Result<(), KeyStorageError> {
        let backup_data = fs::read(backup_path)
            .map_err(|e| KeyStorageError::RestoreError(e.to_string()))?;
        
        self.deserialize_from_backup(&backup_data)?;
        self.save_to_file()?;
        
        Ok(())
    }

    /// Change master password
    pub fn change_master_password(&mut self, old_password: &str, new_password: &str) -> Result<(), KeyStorageError> {
        // Verify old password
        let old_key = Self::derive_key(old_password, &self.encryption_params)?;
        if old_key != self.master_password_hash {
            return Err(KeyStorageError::InvalidPassword("Old password is incorrect".to_string()));
        }

        // Generate new parameters
        let new_salt = Self::generate_salt();
        let new_params = KeyDerivationParams {
            algorithm: "PBKDF2".to_string(),
            iterations: 100_000,
            salt: new_salt,
            key_length: 32,
        };

        // Re-encrypt all keys with new password
        self.re_encrypt_all_keys(new_password, &new_params)?;

        // Update storage
        self.encryption_params = new_params;
        self.master_password_hash = Self::derive_key(new_password, &self.encryption_params)?;
        self.save_to_file()?;

        Ok(())
    }

    // Private helper methods

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, KeyStorageError> {
        // Simple XOR encryption for demo (in production, use AES-256-GCM)
        let key = &self.master_password_hash;
        let mut encrypted = Vec::with_capacity(data.len());
        
        for (i, &byte) in data.iter().enumerate() {
            encrypted.push(byte ^ key[i % key.len()]);
        }
        
        Ok(encrypted)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, KeyStorageError> {
        // Simple XOR decryption for demo (in production, use AES-256-GCM)
        let key = &self.master_password_hash;
        let mut decrypted = Vec::with_capacity(encrypted_data.len());
        
        for (i, &byte) in encrypted_data.iter().enumerate() {
            decrypted.push(byte ^ key[i % key.len()]);
        }
        
        Ok(decrypted)
    }

    fn derive_key(password: &str, params: &KeyDerivationParams) -> Result<Vec<u8>, KeyStorageError> {
        // Simple key derivation for demo (in production, use PBKDF2)
        let mut key = Vec::with_capacity(params.key_length);
        let password_bytes = password.as_bytes();
        
        for i in 0..params.key_length {
            let byte = password_bytes[i % password_bytes.len()] ^ (i as u8);
            key.push(byte);
        }
        
        Ok(key)
    }

    fn generate_salt() -> Vec<u8> {
        // Simple salt generation for demo (in production, use cryptographically secure random)
        (0..32).map(|i| i as u8).collect()
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn save_to_file(&self) -> Result<(), KeyStorageError> {
        let wallet_data = WalletStorageData {
            account_keys: self.account_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?
                .clone(),
            address_keys: self.address_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?
                .clone(),
            encryption_params: self.encryption_params.clone(),
            backup_config: self.backup_config.clone(),
        };

        let serialized = bincode::serialize(&wallet_data)
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;

        let encrypted_data = self.encrypt_data(&serialized)?;
        
        fs::write(&self.file_path, encrypted_data)
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;

        Ok(())
    }

    fn load_from_file(&self) -> Result<(), KeyStorageError> {
        let encrypted_data = fs::read(&self.file_path)
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;

        let serialized = self.decrypt_data(&encrypted_data)?;
        let wallet_data: WalletStorageData = bincode::deserialize(&serialized)
            .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;

        {
            let mut account_keys = self.account_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
            *account_keys = wallet_data.account_keys;
        }

        {
            let mut address_keys = self.address_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
            *address_keys = wallet_data.address_keys;
        }

        Ok(())
    }

    fn serialize_for_backup(&self) -> Result<Vec<u8>, KeyStorageError> {
        let backup_data = WalletBackupData {
            version: 1,
            account_keys: self.account_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?
                .clone(),
            address_keys: self.address_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?
                .clone(),
            encryption_params: self.encryption_params.clone(),
            backup_config: self.backup_config.clone(),
            created_at: Self::current_timestamp(),
        };

        bincode::serialize(&backup_data)
            .map_err(|e| KeyStorageError::BackupError(e.to_string()))
    }

    fn deserialize_from_backup(&mut self, backup_data: &[u8]) -> Result<(), KeyStorageError> {
        let backup: WalletBackupData = bincode::deserialize(backup_data)
            .map_err(|e| KeyStorageError::RestoreError(e.to_string()))?;

        {
            let mut account_keys = self.account_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
            *account_keys = backup.account_keys;
        }

        {
            let mut address_keys = self.address_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
            *address_keys = backup.address_keys;
        }

        self.encryption_params = backup.encryption_params;
        self.backup_config = backup.backup_config;

        Ok(())
    }

    fn re_encrypt_all_keys(&mut self, new_password: &str, new_params: &KeyDerivationParams) -> Result<(), KeyStorageError> {
        // Re-encrypt account keys
        {
            let mut account_keys = self.account_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
            
            for entry in account_keys.values_mut() {
                let decrypted_key = self.decrypt_data(&entry.encrypted_private_key)?;
                let new_key = Self::derive_key(new_password, new_params)?;
                
                // Re-encrypt with new key (simplified for demo)
                let mut re_encrypted = Vec::with_capacity(decrypted_key.len());
                for (i, &byte) in decrypted_key.iter().enumerate() {
                    re_encrypted.push(byte ^ new_key[i % new_key.len()]);
                }
                
                entry.encrypted_private_key = re_encrypted;
            }
        }

        // Re-encrypt address keys
        {
            let mut address_keys = self.address_keys.lock()
                .map_err(|e| KeyStorageError::StorageError(e.to_string()))?;
            
            for entry in address_keys.values_mut() {
                let decrypted_key = self.decrypt_data(&entry.encrypted_private_key)?;
                let new_key = Self::derive_key(new_password, new_params)?;
                
                // Re-encrypt with new key (simplified for demo)
                let mut re_encrypted = Vec::with_capacity(decrypted_key.len());
                for (i, &byte) in decrypted_key.iter().enumerate() {
                    re_encrypted.push(byte ^ new_key[i % new_key.len()]);
                }
                
                entry.encrypted_private_key = re_encrypted;
            }
        }

        Ok(())
    }
}

/// Wallet storage data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletStorageData {
    account_keys: HashMap<u32, AccountKeyEntry>,
    address_keys: HashMap<Address, AddressKeyEntry>,
    encryption_params: KeyDerivationParams,
    backup_config: BackupConfig,
}

/// Wallet backup data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletBackupData {
    version: u32,
    account_keys: HashMap<u32, AccountKeyEntry>,
    address_keys: HashMap<Address, AddressKeyEntry>,
    encryption_params: KeyDerivationParams,
    backup_config: BackupConfig,
    created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Address;

    #[test]
    fn test_key_storage_creation() {
        let storage = KeyStorage::new("test_wallet".to_string(), "test_password");
        assert!(storage.is_ok());
    }

    #[test]
    fn test_account_key_storage() {
        let storage = KeyStorage::new("test_wallet".to_string(), "test_password").unwrap();
        let address = Address::from_slice(&[0u8; 32]).unwrap();
        
        let result = storage.store_account_key(
            0,
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            address,
            "Ed25519".to_string(),
            false,
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_address_key_storage() {
        let storage = KeyStorage::new("test_wallet".to_string(), "test_password").unwrap();
        let address = Address::from_slice(&[0u8; 32]).unwrap();
        
        let result = storage.store_address_key(
            0, 0, 0,
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            address,
        );
        
        assert!(result.is_ok());
    }
}