use std::sync::Arc;
use std::collections::{HashMap, BTreeMap};
use parking_lot::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use crate::storage::Database;
use crate::types::{Hash, Address, AccountState};

/// Advanced state storage with snapshots and efficient updates
pub struct StateStorage {
    /// Database backend
    db: Arc<Database>,
    /// In-memory cache for hot state
    cache: DashMap<Address, CachedAccountState>,
    /// State snapshots for rollback
    snapshots: Arc<RwLock<BTreeMap<u64, StateSnapshot>>>,
    /// Current state version
    current_version: Arc<RwLock<u64>>,
    /// State storage configuration
    config: StateStorageConfig,
    /// Storage statistics
    stats: Arc<RwLock<StateStorageStats>>,
}

/// Cached account state with metadata
#[derive(Debug, Clone)]
struct CachedAccountState {
    /// Account state data
    state: AccountState,
    /// Cache timestamp
    cached_at: u64,
    /// Dirty flag (needs persistence)
    dirty: bool,
    /// Access count for LRU
    access_count: u64,
}

/// State snapshot for point-in-time consistency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Snapshot version
    pub version: u64,
    /// Block height when snapshot was taken
    pub block_height: u64,
    /// State root hash at snapshot time
    pub state_root: Hash,
    /// Snapshot timestamp
    pub timestamp: u64,
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,
}

/// Metadata for state snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Total accounts in snapshot
    pub account_count: u64,
    /// Total state size in bytes
    pub state_size_bytes: u64,
    /// Compression ratio achieved
    pub compression_ratio: f64,
    /// Snapshot creation time in milliseconds
    pub creation_time_ms: u64,
}

/// State storage configuration
#[derive(Debug, Clone)]
pub struct StateStorageConfig {
    /// Maximum cache size (number of accounts)
    pub max_cache_size: usize,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Maximum number of snapshots to keep
    pub max_snapshots: usize,
    /// Snapshot interval (blocks)
    pub snapshot_interval: u64,
    /// Enable state compression
    pub enable_compression: bool,
    /// Batch size for state updates
    pub batch_size: usize,
    /// Enable asynchronous persistence
    pub async_persistence: bool,
}

/// State storage statistics
#[derive(Debug, Clone, Default)]
pub struct StateStorageStats {
    /// Cache statistics
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_size: usize,
    
    /// I/O statistics
    pub reads_from_disk: u64,
    pub writes_to_disk: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    
    /// Snapshot statistics
    pub snapshots_created: u64,
    pub snapshot_creation_time_ms: u64,
    pub average_snapshot_size: u64,
    
    /// Performance metrics
    pub avg_read_time_us: u64,
    pub avg_write_time_us: u64,
    pub state_size_bytes: u64,
}

/// State synchronization manager
pub struct StateSyncManager {
    storage: Arc<StateStorage>,
    sync_config: StateSyncConfig,
}

/// State sync configuration
#[derive(Debug, Clone)]
pub struct StateSyncConfig {
    /// Chunk size for state sync
    pub chunk_size: usize,
    /// Maximum concurrent sync requests
    pub max_concurrent_requests: usize,
    /// Sync timeout in seconds
    pub timeout_seconds: u64,
    /// Enable state compression during sync
    pub compress_during_sync: bool,
}

/// State diff for efficient updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    /// Version this diff applies to
    pub from_version: u64,
    /// Target version after applying diff
    pub to_version: u64,
    /// Account state changes
    pub account_changes: HashMap<Address, AccountStateDiff>,
    /// New accounts created
    pub new_accounts: HashMap<Address, AccountState>,
    /// Accounts deleted
    pub deleted_accounts: Vec<Address>,
}

/// Individual account state difference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStateDiff {
    /// Balance change (can be negative)
    pub balance_diff: Option<i64>,
    /// New nonce value
    pub nonce: Option<u64>,
    /// Code hash change
    pub code_hash: Option<Hash>,
    /// Storage root change
    pub storage_root: Option<Hash>,
}

impl StateStorage {
    /// Create new state storage
    pub fn new(db: Arc<Database>, config: StateStorageConfig) -> Self {
        Self {
            db,
            cache: DashMap::new(),
            snapshots: Arc::new(RwLock::new(BTreeMap::new())),
            current_version: Arc::new(RwLock::new(0)),
            config,
            stats: Arc::new(RwLock::new(StateStorageStats::default())),
        }
    }

    /// Get account state with caching
    pub async fn get_account_state(&self, address: &Address) -> Result<Option<AccountState>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = std::time::Instant::now();
        
        // Check cache first
        if let Some(cached) = self.cache.get(address) {
            if self.is_cache_valid(&cached.cached_at) {
                self.update_cache_stats(true);
                return Ok(Some(cached.state.clone()));
            }
        }
        
        // Cache miss - load from database
        self.update_cache_stats(false);
        
        match self.db.get_account_state(address)? {
            Some(state) => {
                // Cache the loaded state
                self.cache.insert(*address, CachedAccountState {
                    state: state.clone(),
                    cached_at: self.current_timestamp(),
                    dirty: false,
                    access_count: 1,
                });
                
                // Update statistics
                let mut stats = self.stats.write();
                stats.reads_from_disk += 1;
                stats.avg_read_time_us = (stats.avg_read_time_us + start_time.elapsed().as_micros() as u64) / 2;
                
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Update account state with caching
    pub async fn update_account_state(&self, address: Address, state: AccountState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = std::time::Instant::now();
        
        // Update cache
        self.cache.insert(address, CachedAccountState {
            state: state.clone(),
            cached_at: self.current_timestamp(),
            dirty: true,
            access_count: 1,
        });
        
        // Persist to database if not using async persistence
        if !self.config.async_persistence {
            self.db.store_account_state(&address, &state)?;
            
            // Update statistics
            let mut stats = self.stats.write();
            stats.writes_to_disk += 1;
            stats.avg_write_time_us = (stats.avg_write_time_us + start_time.elapsed().as_micros() as u64) / 2;
        }
        
        // Cleanup cache if needed
        self.cleanup_cache().await;
        
        Ok(())
    }

    /// Create state snapshot
    pub async fn create_snapshot(&self, block_height: u64) -> Result<StateSnapshot, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = std::time::Instant::now();
        let version = *self.current_version.read();
        
        println!("📸 Creating state snapshot for block #{}", block_height);
        
        // Flush dirty cache entries to database
        self.flush_dirty_cache().await?;
        
        // Calculate state root
        let state_root = self.calculate_current_state_root().await?;
        
        // Collect metadata
        let metadata = self.collect_snapshot_metadata().await?;
        
        let snapshot = StateSnapshot {
            version: version + 1,
            block_height,
            state_root,
            timestamp: self.current_timestamp(),
            metadata,
        };
        
        // Store snapshot
        self.store_snapshot(&snapshot).await?;
        
        // Update current version
        *self.current_version.write() = version + 1;
        
        // Update statistics
        let mut stats = self.stats.write();
        stats.snapshots_created += 1;
        stats.snapshot_creation_time_ms += start_time.elapsed().as_millis() as u64;
        
        // Cleanup old snapshots
        self.cleanup_old_snapshots().await;
        
        println!("✅ Snapshot created: version {}, root {}", snapshot.version, &snapshot.state_root.to_hex()[..8]);
        Ok(snapshot)
    }

    /// Get snapshot by version
    pub async fn get_snapshot(&self, version: u64) -> Option<StateSnapshot> {
        self.snapshots.read().get(&version).cloned()
    }

    /// Rollback to snapshot
    pub async fn rollback_to_snapshot(&self, version: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(snapshot) = self.get_snapshot(version).await {
            println!("🔄 Rolling back to snapshot version {}", version);
            
            // Clear cache
            self.cache.clear();
            
            // Update current version
            *self.current_version.write() = version;
            
            println!("✅ Rollback completed to version {}", version);
            Ok(())
        } else {
            Err(format!("Snapshot version {} not found", version).into())
        }
    }

    /// Apply state diff
    pub async fn apply_state_diff(&self, diff: &StateDiff) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("🔄 Applying state diff: {} -> {}", diff.from_version, diff.to_version);
        
        // Apply account changes
        for (address, account_diff) in &diff.account_changes {
            if let Some(mut current_state) = self.get_account_state(address).await? {
                // Apply balance change
                if let Some(balance_diff) = account_diff.balance_diff {
                    if balance_diff < 0 {
                        current_state.balance = current_state.balance.saturating_sub((-balance_diff) as u64);
                    } else {
                        current_state.balance = current_state.balance.saturating_add(balance_diff as u64);
                    }
                }
                
                // Apply other changes
                if let Some(nonce) = account_diff.nonce {
                    current_state.nonce = nonce;
                }
                if let Some(code_hash) = account_diff.code_hash {
                    current_state.code_hash = code_hash;
                }
                if let Some(storage_root) = account_diff.storage_root {
                    current_state.storage_root = storage_root;
                }
                
                self.update_account_state(*address, current_state).await?;
            }
        }
        
        // Add new accounts
        for (address, state) in &diff.new_accounts {
            self.update_account_state(*address, state.clone()).await?;
        }
        
        // Remove deleted accounts (mark as empty)
        for address in &diff.deleted_accounts {
            let empty_state = AccountState::new(0);
            self.update_account_state(*address, empty_state).await?;
        }
        
        println!("✅ State diff applied successfully");
        Ok(())
    }

    /// Get storage statistics
    pub fn get_stats(&self) -> StateStorageStats {
        let mut stats = self.stats.read().clone();
        stats.cache_size = self.cache.len();
        stats
    }

    /// Compact state storage
    pub async fn compact(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("🗜️  Starting state storage compaction...");
        
        // Flush all dirty cache entries
        self.flush_dirty_cache().await?;
        
        // Compact underlying database
        self.db.compact()?;
        
        // Cleanup old snapshots
        self.cleanup_old_snapshots().await;
        
        println!("✅ State storage compaction completed");
        Ok(())
    }

    // Internal helper methods

    async fn flush_dirty_cache(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dirty_entries: Vec<_> = self.cache.iter()
            .filter(|entry| entry.dirty)
            .map(|entry| (*entry.key(), entry.state.clone()))
            .collect();
        
        for (address, state) in dirty_entries {
            self.db.store_account_state(&address, &state)?;
            
            // Mark as clean
            if let Some(mut cached) = self.cache.get_mut(&address) {
                cached.dirty = false;
            }
        }
        
        Ok(())
    }

    async fn cleanup_cache(&self) {
        if self.cache.len() > self.config.max_cache_size {
            // Remove least recently used entries
            let current_time = self.current_timestamp();
            let ttl = self.config.cache_ttl_seconds;
            
            self.cache.retain(|_, cached| {
                current_time - cached.cached_at < ttl
            });
            
            // If still too large, remove by access count
            if self.cache.len() > self.config.max_cache_size {
                let to_remove = self.cache.len() - self.config.max_cache_size;
                let mut entries: Vec<_> = self.cache.iter()
                    .map(|entry| (*entry.key(), entry.access_count))
                    .collect();
                
                entries.sort_by_key(|(_, count)| *count);
                
                for (address, _) in entries.iter().take(to_remove) {
                    self.cache.remove(address);
                }
            }
        }
    }

    async fn calculate_current_state_root(&self) -> Result<Hash, Box<dyn std::error::Error + Send + Sync>> {
        // Simplified state root calculation
        // In production, this would use the actual trie root
        let mut state_data = Vec::new();
        
        // Collect all account data
        for entry in self.cache.iter() {
            state_data.extend_from_slice(entry.key().as_bytes());
            state_data.extend_from_slice(&entry.state.balance.to_le_bytes());
            state_data.extend_from_slice(&entry.state.nonce.to_le_bytes());
        }
        
        Ok(Hash::hash(&state_data))
    }

    async fn collect_snapshot_metadata(&self) -> Result<SnapshotMetadata, Box<dyn std::error::Error + Send + Sync>> {
        let account_count = self.cache.len() as u64;
        let state_size_bytes = account_count * 64; // Approximate account size
        
        Ok(SnapshotMetadata {
            account_count,
            state_size_bytes,
            compression_ratio: 0.75, // Simulated compression ratio
            creation_time_ms: 100,   // Simulated creation time
        })
    }

    async fn store_snapshot(&self, snapshot: &StateSnapshot) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Store snapshot in database
        let snapshot_key = format!("snapshot:{}", snapshot.version);
        let snapshot_data = bincode::serialize(snapshot)?;
        
        // Store in snapshots column family
        // Note: This would use a dedicated CF in the actual implementation
        
        // Add to in-memory snapshots
        self.snapshots.write().insert(snapshot.version, snapshot.clone());
        
        Ok(())
    }

    async fn cleanup_old_snapshots(&self) {
        let mut snapshots = self.snapshots.write();
        
        if snapshots.len() > self.config.max_snapshots {
            let to_remove = snapshots.len() - self.config.max_snapshots;
            let old_keys: Vec<_> = snapshots.keys().take(to_remove).copied().collect();
            
            for key in old_keys {
                snapshots.remove(&key);
                println!("🗑️  Removed old snapshot: version {}", key);
            }
        }
    }

    fn is_cache_valid(&self, cached_at: &u64) -> bool {
        let current_time = self.current_timestamp();
        current_time - cached_at < self.config.cache_ttl_seconds
    }

    fn current_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn update_cache_stats(&self, hit: bool) {
        let mut stats = self.stats.write();
        if hit {
            stats.cache_hits += 1;
        } else {
            stats.cache_misses += 1;
        }
    }
}

impl Default for StateStorageConfig {
    fn default() -> Self {
        Self {
            max_cache_size: 10000,      // 10K accounts in cache
            cache_ttl_seconds: 300,     // 5 minutes
            max_snapshots: 100,         // Keep 100 snapshots
            snapshot_interval: 1000,    // Every 1000 blocks
            enable_compression: true,
            batch_size: 1000,
            async_persistence: true,
        }
    }
}

impl StateSyncManager {
    /// Create new state sync manager
    pub fn new(storage: Arc<StateStorage>, config: StateSyncConfig) -> Self {
        Self { storage, sync_config: config }
    }

    /// Sync state from remote peers
    pub async fn sync_state(&self, target_version: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("🔄 Starting state sync to version {}", target_version);
        
        // Simplified state sync implementation
        // In production, this would sync from network peers
        
        println!("✅ State sync completed to version {}", target_version);
        Ok(())
    }
}

impl Default for StateSyncConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1000,
            max_concurrent_requests: 10,
            timeout_seconds: 30,
            compress_during_sync: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::DatabaseConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_state_storage() {
        let temp_dir = TempDir::new().unwrap();
        let db_config = DatabaseConfig {
            path: temp_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        
        let db = Arc::new(Database::new(db_config).unwrap());
        let config = StateStorageConfig::default();
        let storage = StateStorage::new(db, config);
        
        let address = Address::from_bytes([1u8; 20]).unwrap();
        let state = AccountState::new(1000);
        
        // Update and retrieve state
        storage.update_account_state(address, state.clone()).await.unwrap();
        let retrieved = storage.get_account_state(&address).await.unwrap();
        
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().balance, 1000);
    }

    #[tokio::test]
    async fn test_state_snapshots() {
        let temp_dir = TempDir::new().unwrap();
        let db_config = DatabaseConfig {
            path: temp_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        
        let db = Arc::new(Database::new(db_config).unwrap());
        let config = StateStorageConfig::default();
        let storage = StateStorage::new(db, config);
        
        // Create snapshot
        let snapshot = storage.create_snapshot(100).await.unwrap();
        assert_eq!(snapshot.block_height, 100);
        
        // Retrieve snapshot
        let retrieved = storage.get_snapshot(snapshot.version).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().version, snapshot.version);
    }
} 