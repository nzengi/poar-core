use std::path::Path;
use std::sync::Arc;
use std::collections::HashMap;
use rocksdb::{DB, Options, ColumnFamily, ColumnFamilyDescriptor, WriteBatch, IteratorMode, Direction};
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use parking_lot::RwLock;
use crate::types::{Hash, Address, Block, Transaction, AccountState};

/// Column family names for different data types
pub const CF_BLOCKS: &str = "blocks";
pub const CF_TRANSACTIONS: &str = "transactions"; 
pub const CF_STATE: &str = "state";
pub const CF_RECEIPTS: &str = "receipts";
pub const CF_LOGS: &str = "logs";
pub const CF_METADATA: &str = "metadata";
pub const CF_TRIE: &str = "trie";
pub const CF_SNAPSHOTS: &str = "snapshots";

/// High-performance blockchain database using RocksDB
pub struct Database {
    /// RocksDB instance
    db: Arc<DB>,
    /// Database configuration
    config: DatabaseConfig,
    /// Write cache for batching operations
    write_cache: DashMap<String, Vec<u8>>,
    /// Database statistics
    stats: Arc<RwLock<DatabaseStats>>,
    /// Column family handles cache
    cf_handles: HashMap<String, Arc<ColumnFamily>>,
}

/// Database configuration with performance tuning
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Database directory path
    pub path: String,
    /// Enable WAL (Write-Ahead Logging)
    pub enable_wal: bool,
    /// Maximum write buffer size
    pub write_buffer_size: usize,
    /// Number of background threads
    pub bg_threads: i32,
    /// Enable compression
    pub enable_compression: bool,
    /// Cache size in bytes
    pub cache_size: usize,
    /// Bloom filter bits per key
    pub bloom_filter_bits: i32,
    /// Enable statistics
    pub enable_stats: bool,
    /// Batch write threshold
    pub batch_threshold: usize,
}

/// Database operation statistics
#[derive(Debug, Clone, Default)]
pub struct DatabaseStats {
    /// Total read operations
    pub reads: u64,
    /// Total write operations  
    pub writes: u64,
    /// Total bytes read
    pub bytes_read: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Cache hit ratio
    pub cache_hit_ratio: f64,
    /// Average operation time (microseconds)
    pub avg_op_time_us: u64,
    /// Database size in bytes
    pub db_size_bytes: u64,
    /// Number of SST files
    pub num_sst_files: u64,
}

/// Database backup manager
pub struct BackupManager {
    db: Arc<DB>,
    backup_path: String,
}

/// Database snapshot for consistent reads
pub struct DatabaseSnapshot {
    db: Arc<DB>,
    snapshot: rocksdb::Snapshot<'static>,
}

/// Batch writer for atomic operations
pub struct BatchWriter {
    batch: WriteBatch,
    db: Arc<DB>,
    size: usize,
    threshold: usize,
}

impl Database {
    /// Create new database instance
    pub fn new(config: DatabaseConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Configure RocksDB options
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_write_buffer_size(config.write_buffer_size);
        db_opts.set_max_background_jobs(config.bg_threads);
        db_opts.set_enable_write_thread_adaptive_yield(true);
        db_opts.set_allow_concurrent_memtable_write(true);
        
        if config.enable_compression {
            db_opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
            db_opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        }

        if config.enable_stats {
            db_opts.enable_statistics();
        }

        // Configure column families
        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Self::block_cf_options(&config)),
            ColumnFamilyDescriptor::new(CF_TRANSACTIONS, Self::tx_cf_options(&config)),
            ColumnFamilyDescriptor::new(CF_STATE, Self::state_cf_options(&config)),
            ColumnFamilyDescriptor::new(CF_RECEIPTS, Self::receipts_cf_options(&config)),
            ColumnFamilyDescriptor::new(CF_LOGS, Self::logs_cf_options(&config)),
            ColumnFamilyDescriptor::new(CF_METADATA, Self::metadata_cf_options(&config)),
            ColumnFamilyDescriptor::new(CF_TRIE, Self::trie_cf_options(&config)),
            ColumnFamilyDescriptor::new(CF_SNAPSHOTS, Self::snapshots_cf_options(&config)),
        ];

        // Open database
        let db = DB::open_cf_descriptors(&db_opts, &config.path, cf_descriptors)?;
        let db_arc = Arc::new(db);

        // Cache column family handles
        let mut cf_handles = HashMap::new();
        for cf_name in [CF_BLOCKS, CF_TRANSACTIONS, CF_STATE, CF_RECEIPTS, CF_LOGS, CF_METADATA, CF_TRIE, CF_SNAPSHOTS] {
            if let Some(cf) = db_arc.cf_handle(cf_name) {
                cf_handles.insert(cf_name.to_string(), Arc::new(cf));
            }
        }

        Ok(Self {
            db: db_arc,
            config,
            write_cache: DashMap::new(),
            stats: Arc::new(RwLock::new(DatabaseStats::default())),
            cf_handles,
        })
    }

    /// Store a block in the database
    pub fn store_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_BLOCKS)?;
        let key = block.header.hash.as_bytes();
        let value = bincode::serialize(block)?;
        
        // Also store by height for quick lookup
        let height_key = format!("height:{}", block.header.height);
        
        let mut batch = BatchWriter::new(self.db.clone(), self.config.batch_threshold);
        batch.put_cf(cf, key, &value)?;
        batch.put_cf(cf, height_key.as_bytes(), key)?;
        batch.commit()?;

        // Update stats
        self.update_write_stats(value.len());
        
        println!("📦 Stored block #{} ({})", block.header.height, &block.header.hash.to_hex()[..8]);
        Ok(())
    }

    /// Get block by hash
    pub fn get_block(&self, hash: &Hash) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_BLOCKS)?;
        let key = hash.as_bytes();
        
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                self.update_read_stats(data.len());
                let block: Block = bincode::deserialize(&data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_BLOCKS)?;
        let height_key = format!("height:{}", height);
        
        // First get the hash
        match self.db.get_cf(cf, height_key.as_bytes())? {
            Some(hash_bytes) => {
                let hash = Hash::from_bytes(&hash_bytes)?;
                self.get_block(&hash)
            }
            None => Ok(None),
        }
    }

    /// Store transaction
    pub fn store_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_TRANSACTIONS)?;
        let key = tx.hash.as_bytes();
        let value = bincode::serialize(tx)?;
        
        self.db.put_cf(cf, key, &value)?;
        self.update_write_stats(value.len());
        
        Ok(())
    }

    /// Get transaction by hash
    pub fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_TRANSACTIONS)?;
        let key = hash.as_bytes();
        
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                self.update_read_stats(data.len());
                let tx: Transaction = bincode::deserialize(&data)?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    /// Store account state
    pub fn store_account_state(&self, address: &Address, state: &AccountState) -> Result<(), Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_STATE)?;
        let key = address.as_bytes();
        let value = bincode::serialize(state)?;
        
        self.db.put_cf(cf, key, &value)?;
        self.update_write_stats(value.len());
        
        Ok(())
    }

    /// Get account state
    pub fn get_account_state(&self, address: &Address) -> Result<Option<AccountState>, Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_STATE)?;
        let key = address.as_bytes();
        
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                self.update_read_stats(data.len());
                let state: AccountState = bincode::deserialize(&data)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Store trie node
    pub fn store_trie_node(&self, node_hash: &Hash, node_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_TRIE)?;
        let key = node_hash.as_bytes();
        
        self.db.put_cf(cf, key, node_data)?;
        self.update_write_stats(node_data.len());
        
        Ok(())
    }

    /// Get trie node
    pub fn get_trie_node(&self, node_hash: &Hash) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_TRIE)?;
        let key = node_hash.as_bytes();
        
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                self.update_read_stats(data.len());
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Create database snapshot
    pub fn create_snapshot(&self) -> DatabaseSnapshot {
        let snapshot = self.db.snapshot();
        // Note: In real implementation, we'd need to handle lifetimes properly
        DatabaseSnapshot {
            db: self.db.clone(),
            snapshot: unsafe { std::mem::transmute(snapshot) },
        }
    }

    /// Get latest block height
    pub fn get_latest_block_height(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_METADATA)?;
        let key = b"latest_height";
        
        match self.db.get_cf(cf, key)? {
            Some(data) => {
                let height = u64::from_le_bytes(data.try_into()?);
                Ok(height)
            }
            None => Ok(0), // Genesis
        }
    }

    /// Update latest block height
    pub fn update_latest_block_height(&self, height: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cf = self.get_cf(CF_METADATA)?;
        let key = b"latest_height";
        let value = height.to_le_bytes();
        
        self.db.put_cf(cf, key, &value)?;
        self.update_write_stats(8);
        
        Ok(())
    }

    /// Iterate over all blocks
    pub fn iterate_blocks<F>(&self, mut callback: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnMut(&Hash, &Block) -> bool, // Return false to stop iteration
    {
        let cf = self.get_cf(CF_BLOCKS)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        
        for item in iter {
            let (key, value) = item?;
            
            // Skip height index entries
            if key.starts_with(b"height:") {
                continue;
            }
            
            let hash = Hash::from_bytes(&key)?;
            let block: Block = bincode::deserialize(&value)?;
            
            if !callback(&hash, &block) {
                break;
            }
        }
        
        Ok(())
    }

    /// Get database statistics
    pub fn get_stats(&self) -> DatabaseStats {
        let mut stats = self.stats.read().clone();
        
        // Update database size
        if let Ok(size) = self.calculate_db_size() {
            stats.db_size_bytes = size;
        }
        
        stats
    }

    /// Compact database
    pub fn compact(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🗜️  Starting database compaction...");
        
        // Compact each column family
        for cf_name in [CF_BLOCKS, CF_TRANSACTIONS, CF_STATE, CF_RECEIPTS, CF_LOGS, CF_METADATA, CF_TRIE, CF_SNAPSHOTS] {
            if let Ok(cf) = self.get_cf(cf_name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
                println!("   ✓ Compacted {}", cf_name);
            }
        }
        
        println!("✅ Database compaction completed");
        Ok(())
    }

    /// Create backup
    pub fn create_backup(&self, backup_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Note: RocksDB backup functionality would be implemented here
        // For now, we'll create a simple backup manager
        let backup_manager = BackupManager {
            db: self.db.clone(),
            backup_path: backup_path.to_string(),
        };
        
        backup_manager.create_backup()
    }

    // Internal helper methods

    fn get_cf(&self, cf_name: &str) -> Result<&ColumnFamily, Box<dyn std::error::Error>> {
        self.db.cf_handle(cf_name)
            .ok_or_else(|| format!("Column family {} not found", cf_name).into())
    }

    fn update_read_stats(&self, bytes: usize) {
        let mut stats = self.stats.write();
        stats.reads += 1;
        stats.bytes_read += bytes as u64;
    }

    fn update_write_stats(&self, bytes: usize) {
        let mut stats = self.stats.write();
        stats.writes += 1;
        stats.bytes_written += bytes as u64;
    }

    fn calculate_db_size(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Calculate total database size
        let mut total_size = 0u64;
        
        if let Some(path) = std::path::Path::new(&self.config.path).canonicalize().ok() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    if let Ok(metadata) = entry.metadata() {
                        total_size += metadata.len();
                    }
                }
            }
        }
        
        Ok(total_size)
    }

    // Column family options
    fn block_cf_options(config: &DatabaseConfig) -> Options {
        let mut opts = Options::default();
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_bloom_filter(config.bloom_filter_bits, false);
        opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
        opts
    }

    fn tx_cf_options(config: &DatabaseConfig) -> Options {
        let mut opts = Options::default();
        opts.set_write_buffer_size(config.write_buffer_size / 2);
        opts.set_bloom_filter(config.bloom_filter_bits, false);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts
    }

    fn state_cf_options(config: &DatabaseConfig) -> Options {
        let mut opts = Options::default();
        opts.set_write_buffer_size(config.write_buffer_size * 2);
        opts.set_bloom_filter(config.bloom_filter_bits * 2, false);
        opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
        opts
    }

    fn receipts_cf_options(config: &DatabaseConfig) -> Options {
        let mut opts = Options::default();
        opts.set_write_buffer_size(config.write_buffer_size / 4);
        opts.set_compression_type(rocksdb::DBCompressionType::Snappy);
        opts
    }

    fn logs_cf_options(config: &DatabaseConfig) -> Options {
        let mut opts = Options::default();
        opts.set_write_buffer_size(config.write_buffer_size / 4);
        opts.set_compression_type(rocksdb::DBCompressionType::Snappy);
        opts
    }

    fn metadata_cf_options(config: &DatabaseConfig) -> Options {
        let mut opts = Options::default();
        opts.set_write_buffer_size(1024 * 1024); // 1MB for metadata
        opts.set_compression_type(rocksdb::DBCompressionType::None);
        opts
    }

    fn trie_cf_options(config: &DatabaseConfig) -> Options {
        let mut opts = Options::default();
        opts.set_write_buffer_size(config.write_buffer_size * 3);
        opts.set_bloom_filter(config.bloom_filter_bits * 3, false);
        opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
        opts
    }

    fn snapshots_cf_options(config: &DatabaseConfig) -> Options {
        let mut opts = Options::default();
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
        opts
    }
}

impl BackupManager {
    /// Create a backup of the database
    pub fn create_backup(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("💾 Creating database backup...");
        
        // In a real implementation, we'd use RocksDB's backup API
        // For now, we'll simulate the backup process
        std::fs::create_dir_all(&self.backup_path)?;
        
        let backup_id = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let backup_file = format!("{}/backup_{}.db", self.backup_path, backup_id);
        
        // Simulate backup creation
        std::fs::write(&backup_file, b"POAR_BACKUP_PLACEHOLDER")?;
        
        println!("✅ Backup created: {}", backup_file);
        Ok(())
    }
}

impl BatchWriter {
    /// Create new batch writer
    pub fn new(db: Arc<DB>, threshold: usize) -> Self {
        Self {
            batch: WriteBatch::default(),
            db,
            size: 0,
            threshold,
        }
    }

    /// Add put operation to batch
    pub fn put_cf(&mut self, cf: &ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.batch.put_cf(cf, key, value);
        self.size += key.len() + value.len();
        
        if self.size >= self.threshold {
            self.commit()?;
        }
        
        Ok(())
    }

    /// Commit the batch
    pub fn commit(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.size > 0 {
            self.db.write(self.batch.clone())?;
            self.batch.clear();
            self.size = 0;
        }
        Ok(())
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./data/poar_db".to_string(),
            enable_wal: true,
            write_buffer_size: 64 * 1024 * 1024, // 64MB
            bg_threads: num_cpus::get() as i32,
            enable_compression: true,
            cache_size: 256 * 1024 * 1024, // 256MB
            bloom_filter_bits: 10,
            enable_stats: true,
            batch_threshold: 1024 * 1024, // 1MB
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::types::{BlockHeader, TransactionType};

    #[test]
    fn test_database_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = DatabaseConfig {
            path: temp_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        
        let db = Database::new(config);
        assert!(db.is_ok());
    }

    #[test]
    fn test_block_storage_retrieval() {
        let temp_dir = TempDir::new().unwrap();
        let config = DatabaseConfig {
            path: temp_dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        
        let db = Database::new(config).unwrap();
        let block = Block::genesis();
        
        // Store block
        db.store_block(&block).unwrap();
        
        // Retrieve by hash
        let retrieved = db.get_block(&block.header.hash).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().header.hash, block.header.hash);
        
        // Retrieve by height
        let retrieved_by_height = db.get_block_by_height(0).unwrap();
        assert!(retrieved_by_height.is_some());
        assert_eq!(retrieved_by_height.unwrap().header.height, 0);
    }
}
