use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, generic_array::GenericArray}};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey};
use pbkdf2::pbkdf2_hmac;
use scrypt::{Scrypt, Params as ScryptParams};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use keyring::{Entry, Error as KeyringError};
use directories::ProjectDirs;
use rand_core::{OsRng, RngCore};
use crate::types::Address;

/// Secure key storage manager
pub struct KeyStorage {
    /// Storage configuration
    config: StorageConfig,
    /// OS keychain integration
    keychain: Option<KeychainStorage>,
    /// File-based storage
    file_storage: FileStorage,
    /// In-memory cache (encrypted)
    cache: HashMap<String, EncryptedData>,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage directory
    pub storage_dir: PathBuf,
    /// Enable OS keychain
    pub use_keychain: bool,
    /// Enable file encryption
    pub encrypt_files: bool,
    /// Encryption algorithm
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Key derivation algorithm
    pub key_derivation: KeyDerivationAlgorithm,
    /// PBKDF2 iterations
    pub pbkdf2_iterations: u32,
    /// Scrypt parameters
    pub scrypt_params: ScryptConfig,
    /// Auto-lock timeout (seconds)
    pub auto_lock_timeout: u64,
}

/// Encryption algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncryptionAlgorithm {
    AesGcm256,
    ChaCha20Poly1305,
}

/// Key derivation algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyDerivationAlgorithm {
    Pbkdf2,
    Scrypt,
    Argon2,
}

/// Scrypt configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptConfig {
    pub n: u32,
    pub r: u32,
    pub p: u32,
}

/// OS keychain storage
pub struct KeychainStorage {
    /// Service name for keychain entries
    service: String,
    /// Application name
    app_name: String,
}

/// File-based storage
pub struct FileStorage {
    /// Base storage directory
    storage_dir: PathBuf,
    /// Master key file
    master_key_file: PathBuf,
    /// Accounts directory
    accounts_dir: PathBuf,
    /// Configuration file
    config_file: PathBuf,
}

/// Encrypted data container
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct EncryptedData {
    /// Encryption algorithm used
    pub algorithm: EncryptionAlgorithm,
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// Initialization vector/nonce
    pub nonce: Vec<u8>,
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Authentication tag (for AEAD)
    pub tag: Option<Vec<u8>>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Master key entry
#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct MasterKeyEntry {
    /// Encrypted master private key
    pub encrypted_key: EncryptedData,
    /// Key derivation parameters
    pub derivation_params: KeyDerivationParams,
    /// Creation timestamp
    pub created_at: u64,
    /// Last access timestamp
    pub last_accessed: u64,
}

/// Account key entry
#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct AccountKeyEntry {
    /// Account index
    pub account_index: u32,
    /// Account name
    pub account_name: String,
    /// Encrypted extended private key
    pub encrypted_key: EncryptedData,
    /// Extended public key (not encrypted)
    pub extended_public_key: String,
    /// Associated addresses
    pub addresses: Vec<AddressKeyEntry>,
    /// Creation timestamp
    pub created_at: u64,
}

/// Address key entry
#[derive(Debug, Serialize, Deserialize)]
pub struct AddressKeyEntry {
    /// Address index
    pub address_index: u32,
    /// Ethereum address
    pub address: Address,
    /// Derivation path
    pub derivation_path: String,
    /// Address type (receiving/change)
    pub address_type: String,
    /// Public key
    pub public_key: String,
    /// Label/name
    pub label: Option<String>,
}

/// Key derivation parameters
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    /// Algorithm used
    pub algorithm: KeyDerivationAlgorithm,
    /// Salt
    pub salt: Vec<u8>,
    /// PBKDF2 iterations (if applicable)
    pub iterations: Option<u32>,
    /// Scrypt parameters (if applicable)
    pub scrypt_params: Option<ScryptConfig>,
}

/// Secure password wrapper
#[derive(ZeroizeOnDrop)]
pub struct SecurePassword {
    password: String,
}

/// Storage errors
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Keychain error: {0}")]
    KeychainError(String),
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Storage locked")]
    StorageLocked,
}

impl KeyStorage {
    /// Create new key storage
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        println!("🔐 Initializing secure key storage...");

        // Create storage directories
        fs::create_dir_all(&config.storage_dir)?;
        
        let file_storage = FileStorage::new(&config.storage_dir)?;
        
        let keychain = if config.use_keychain {
            Some(KeychainStorage::new()?)
        } else {
            None
        };

        println!("   Storage directory: {:?}", config.storage_dir);
        println!("   OS keychain: {}", if config.use_keychain { "enabled" } else { "disabled" });
        println!("   Encryption: {:?}", config.encryption_algorithm);

        Ok(Self {
            config,
            keychain,
            file_storage,
            cache: HashMap::new(),
        })
    }

    /// Store master key
    pub fn store_master_key(&mut self, key_data: &[u8], password: &SecurePassword) -> Result<(), StorageError> {
        println!("🔑 Storing master key...");

        let derivation_params = self.generate_key_derivation_params();
        let encryption_key = self.derive_encryption_key(password, &derivation_params)?;
        
        let encrypted_data = self.encrypt_data(key_data, &encryption_key)?;
        
        let master_key_entry = MasterKeyEntry {
            encrypted_key: encrypted_data,
            derivation_params,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_accessed: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Store in file
        self.file_storage.store_master_key(&master_key_entry)?;

        // Store in keychain if enabled
        if let Some(ref keychain) = self.keychain {
            keychain.store_master_key_reference("master_key", &self.file_storage.master_key_file)?;
        }

        println!("✅ Master key stored securely");
        Ok(())
    }

    /// Load master key
    pub fn load_master_key(&mut self, password: &SecurePassword) -> Result<Vec<u8>, StorageError> {
        println!("🔓 Loading master key...");

        let master_key_entry = self.file_storage.load_master_key()?;
        let encryption_key = self.derive_encryption_key(password, &master_key_entry.derivation_params)?;
        
        let decrypted_data = self.decrypt_data(&master_key_entry.encrypted_key, &encryption_key)?;

        println!("✅ Master key loaded successfully");
        Ok(decrypted_data)
    }

    /// Store account key
    pub fn store_account_key(&mut self, account_entry: &AccountKeyEntry, password: &SecurePassword) -> Result<(), StorageError> {
        println!("👤 Storing account key for account {}", account_entry.account_index);

        let serialized = serde_json::to_vec(account_entry)?;
        let derivation_params = self.generate_key_derivation_params();
        let encryption_key = self.derive_encryption_key(password, &derivation_params)?;
        
        let encrypted_data = self.encrypt_data(&serialized, &encryption_key)?;
        
        self.file_storage.store_account_key(account_entry.account_index, &encrypted_data)?;
        
        // Cache encrypted data
        let cache_key = format!("account_{}", account_entry.account_index);
        self.cache.insert(cache_key, encrypted_data);

        println!("✅ Account key stored securely");
        Ok(())
    }

    /// Load account key
    pub fn load_account_key(&mut self, account_index: u32, password: &SecurePassword) -> Result<AccountKeyEntry, StorageError> {
        println!("🔓 Loading account key for account {}", account_index);

        let cache_key = format!("account_{}", account_index);
        
        // Check cache first
        let encrypted_data = if let Some(cached) = self.cache.get(&cache_key) {
            cached.clone()
        } else {
            let data = self.file_storage.load_account_key(account_index)?;
            self.cache.insert(cache_key, data.clone());
            data
        };

        // For this example, we'll use the same derivation params as master key
        // In practice, you'd store derivation params with each account
        let derivation_params = self.generate_key_derivation_params();
        let encryption_key = self.derive_encryption_key(password, &derivation_params)?;
        
        let decrypted_data = self.decrypt_data(&encrypted_data, &encryption_key)?;
        let account_entry: AccountKeyEntry = serde_json::from_slice(&decrypted_data)?;

        println!("✅ Account key loaded successfully");
        Ok(account_entry)
    }

    /// List stored accounts
    pub fn list_accounts(&self) -> Result<Vec<u32>, StorageError> {
        self.file_storage.list_accounts()
    }

    /// Delete account key
    pub fn delete_account_key(&mut self, account_index: u32) -> Result<(), StorageError> {
        println!("🗑️  Deleting account key for account {}", account_index);

        self.file_storage.delete_account_key(account_index)?;
        
        let cache_key = format!("account_{}", account_index);
        self.cache.remove(&cache_key);

        println!("✅ Account key deleted");
        Ok(())
    }

    /// Clear cache (for security)
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        println!("🧹 Key cache cleared");
    }

    /// Change password
    pub fn change_password(&mut self, old_password: &SecurePassword, new_password: &SecurePassword) -> Result<(), StorageError> {
        println!("🔄 Changing storage password...");

        // Load master key with old password
        let master_key_data = self.load_master_key(old_password)?;

        // Re-encrypt with new password
        self.store_master_key(&master_key_data, new_password)?;

        // Re-encrypt all account keys
        let account_indices = self.list_accounts()?;
        for account_index in account_indices {
            let account_entry = self.load_account_key(account_index, old_password)?;
            self.store_account_key(&account_entry, new_password)?;
        }

        println!("✅ Password changed successfully");
        Ok(())
    }

    /// Encrypt data
    fn encrypt_data(&self, data: &[u8], key: &[u8]) -> Result<EncryptedData, StorageError> {
        match self.config.encryption_algorithm {
            EncryptionAlgorithm::AesGcm256 => {
                let key = Key::<Aes256Gcm>::from_slice(key);
                let cipher = Aes256Gcm::new(key);
                
                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                let ciphertext = cipher.encrypt(nonce, data)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

                Ok(EncryptedData {
                    algorithm: EncryptionAlgorithm::AesGcm256,
                    salt: vec![], // Salt is handled in key derivation
                    nonce: nonce_bytes.to_vec(),
                    ciphertext,
                    tag: None, // AES-GCM includes auth tag in ciphertext
                    metadata: HashMap::new(),
                })
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let key = ChaChaKey::from_slice(key);
                let cipher = ChaCha20Poly1305::new(key);
                
                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = GenericArray::from_slice(&nonce_bytes);
                
                let ciphertext = cipher.encrypt(nonce, data)
                    .map_err(|e| StorageError::EncryptionError(e.to_string()))?;

                Ok(EncryptedData {
                    algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
                    salt: vec![],
                    nonce: nonce_bytes.to_vec(),
                    ciphertext,
                    tag: None,
                    metadata: HashMap::new(),
                })
            }
        }
    }

    /// Decrypt data
    fn decrypt_data(&self, encrypted_data: &EncryptedData, key: &[u8]) -> Result<Vec<u8>, StorageError> {
        match encrypted_data.algorithm {
            EncryptionAlgorithm::AesGcm256 => {
                let key = Key::<Aes256Gcm>::from_slice(key);
                let cipher = Aes256Gcm::new(key);
                let nonce = Nonce::from_slice(&encrypted_data.nonce);
                
                cipher.decrypt(nonce, encrypted_data.ciphertext.as_ref())
                    .map_err(|e| StorageError::DecryptionError(e.to_string()))
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let key = ChaChaKey::from_slice(key);
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = GenericArray::from_slice(&encrypted_data.nonce);
                
                cipher.decrypt(nonce, encrypted_data.ciphertext.as_ref())
                    .map_err(|e| StorageError::DecryptionError(e.to_string()))
            }
        }
    }

    /// Generate key derivation parameters
    fn generate_key_derivation_params(&self) -> KeyDerivationParams {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        KeyDerivationParams {
            algorithm: self.config.key_derivation.clone(),
            salt: salt.to_vec(),
            iterations: Some(self.config.pbkdf2_iterations),
            scrypt_params: Some(self.config.scrypt_params.clone()),
        }
    }

    /// Derive encryption key from password
    fn derive_encryption_key(&self, password: &SecurePassword, params: &KeyDerivationParams) -> Result<Vec<u8>, StorageError> {
        let mut key = vec![0u8; 32]; // 256-bit key

        match params.algorithm {
            KeyDerivationAlgorithm::Pbkdf2 => {
                let iterations = params.iterations.unwrap_or(100_000);
                pbkdf2_hmac::<Sha256>(
                    password.password.as_bytes(),
                    &params.salt,
                    iterations,
                    &mut key,
                );
            }
            KeyDerivationAlgorithm::Scrypt => {
                let scrypt_params = params.scrypt_params.as_ref().unwrap();
                let params = ScryptParams::new(
                    scrypt_params.n.ilog2() as u8,
                    scrypt_params.r,
                    scrypt_params.p,
                    32,
                ).map_err(|e| StorageError::EncryptionError(e.to_string()))?;

                scrypt::scrypt(
                    password.password.as_bytes(),
                    &params.salt,
                    &params,
                    &mut key,
                ).map_err(|e| StorageError::EncryptionError(e.to_string()))?;
            }
            KeyDerivationAlgorithm::Argon2 => {
                // Argon2 implementation would go here
                return Err(StorageError::EncryptionError("Argon2 not implemented".to_string()));
            }
        }

        Ok(key)
    }
}

impl KeychainStorage {
    /// Create new keychain storage
    pub fn new() -> Result<Self, StorageError> {
        Ok(Self {
            service: "poar-wallet".to_string(),
            app_name: "POAR".to_string(),
        })
    }

    /// Store master key reference in keychain
    pub fn store_master_key_reference(&self, key_name: &str, file_path: &Path) -> Result<(), StorageError> {
        let entry = Entry::new(&self.service, key_name)
            .map_err(|e| StorageError::KeychainError(e.to_string()))?;

        let path_str = file_path.to_string_lossy();
        entry.set_password(&path_str)
            .map_err(|e| StorageError::KeychainError(e.to_string()))?;

        println!("🔗 Master key reference stored in OS keychain");
        Ok(())
    }

    /// Get master key reference from keychain
    pub fn get_master_key_reference(&self, key_name: &str) -> Result<PathBuf, StorageError> {
        let entry = Entry::new(&self.service, key_name)
            .map_err(|e| StorageError::KeychainError(e.to_string()))?;

        let path_str = entry.get_password()
            .map_err(|e| StorageError::KeychainError(e.to_string()))?;

        Ok(PathBuf::from(path_str))
    }

    /// Delete entry from keychain
    pub fn delete_entry(&self, key_name: &str) -> Result<(), StorageError> {
        let entry = Entry::new(&self.service, key_name)
            .map_err(|e| StorageError::KeychainError(e.to_string()))?;

        entry.delete_password()
            .map_err(|e| StorageError::KeychainError(e.to_string()))?;

        Ok(())
    }
}

impl FileStorage {
    /// Create new file storage
    pub fn new(storage_dir: &Path) -> Result<Self, StorageError> {
        let accounts_dir = storage_dir.join("accounts");
        fs::create_dir_all(&accounts_dir)?;

        Ok(Self {
            storage_dir: storage_dir.to_path_buf(),
            master_key_file: storage_dir.join("master_key.json"),
            accounts_dir,
            config_file: storage_dir.join("config.json"),
        })
    }

    /// Store master key
    pub fn store_master_key(&self, entry: &MasterKeyEntry) -> Result<(), StorageError> {
        let json = serde_json::to_string_pretty(entry)?;
        fs::write(&self.master_key_file, json)?;
        Ok(())
    }

    /// Load master key
    pub fn load_master_key(&self) -> Result<MasterKeyEntry, StorageError> {
        let json = fs::read_to_string(&self.master_key_file)?;
        let entry = serde_json::from_str(&json)?;
        Ok(entry)
    }

    /// Store account key
    pub fn store_account_key(&self, account_index: u32, encrypted_data: &EncryptedData) -> Result<(), StorageError> {
        let file_path = self.accounts_dir.join(format!("account_{}.json", account_index));
        let json = serde_json::to_string_pretty(encrypted_data)?;
        fs::write(file_path, json)?;
        Ok(())
    }

    /// Load account key
    pub fn load_account_key(&self, account_index: u32) -> Result<EncryptedData, StorageError> {
        let file_path = self.accounts_dir.join(format!("account_{}.json", account_index));
        let json = fs::read_to_string(file_path)?;
        let encrypted_data = serde_json::from_str(&json)?;
        Ok(encrypted_data)
    }

    /// List accounts
    pub fn list_accounts(&self) -> Result<Vec<u32>, StorageError> {
        let mut accounts = Vec::new();
        
        for entry in fs::read_dir(&self.accounts_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            
            if file_name.starts_with("account_") && file_name.ends_with(".json") {
                let index_str = &file_name[8..file_name.len()-5]; // Remove "account_" and ".json"
                if let Ok(index) = index_str.parse::<u32>() {
                    accounts.push(index);
                }
            }
        }
        
        accounts.sort();
        Ok(accounts)
    }

    /// Delete account key
    pub fn delete_account_key(&self, account_index: u32) -> Result<(), StorageError> {
        let file_path = self.accounts_dir.join(format!("account_{}.json", account_index));
        if file_path.exists() {
            fs::remove_file(file_path)?;
        }
        Ok(())
    }
}

impl SecurePassword {
    /// Create secure password from string
    pub fn new(password: String) -> Self {
        Self { password }
    }

    /// Get password (use carefully)
    pub fn reveal(&self) -> &str {
        &self.password
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        let project_dirs = ProjectDirs::from("com", "poar", "wallet")
            .expect("Failed to get project directories");
        
        Self {
            storage_dir: project_dirs.data_dir().to_path_buf(),
            use_keychain: true,
            encrypt_files: true,
            encryption_algorithm: EncryptionAlgorithm::AesGcm256,
            key_derivation: KeyDerivationAlgorithm::Pbkdf2,
            pbkdf2_iterations: 100_000,
            scrypt_params: ScryptConfig {
                n: 32768,
                r: 8,
                p: 1,
            },
            auto_lock_timeout: 300, // 5 minutes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_key_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_dir: temp_dir.path().to_path_buf(),
            use_keychain: false, // Disable for testing
            ..Default::default()
        };

        let storage = KeyStorage::new(config).unwrap();
        assert!(temp_dir.path().exists());
    }

    #[test]
    fn test_encryption_decryption() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_dir: temp_dir.path().to_path_buf(),
            use_keychain: false,
            ..Default::default()
        };

        let mut storage = KeyStorage::new(config).unwrap();
        let password = SecurePassword::new("test_password".to_string());
        let test_data = b"Hello, World!";

        // Test master key storage and retrieval
        storage.store_master_key(test_data, &password).unwrap();
        let retrieved_data = storage.load_master_key(&password).unwrap();

        assert_eq!(test_data, retrieved_data.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            storage_dir: temp_dir.path().to_path_buf(),
            use_keychain: false,
            key_derivation: KeyDerivationAlgorithm::Pbkdf2,
            pbkdf2_iterations: 1000, // Faster for testing
            ..Default::default()
        };

        let storage = KeyStorage::new(config).unwrap();
        let password = SecurePassword::new("test_password".to_string());
        let params = storage.generate_key_derivation_params();
        
        let key1 = storage.derive_encryption_key(&password, &params).unwrap();
        let key2 = storage.derive_encryption_key(&password, &params).unwrap();
        
        assert_eq!(key1, key2); // Same password and params should produce same key
        assert_eq!(key1.len(), 32); // 256-bit key
    }
} 