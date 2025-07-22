use rocksdb::{DB, Options, Error as RocksDbError, Checkpoint};
use crate::consensus::engine::ConsensusState;
use crate::storage::state::StateTrie;
use crate::types::Transaction;
use bincode;

/// Persistent storage for consensus state, state trie, and pending transactions using RocksDB.
pub struct PersistentStorage {
    db: DB,
}

impl PersistentStorage {
    /// Open or create a RocksDB instance at the given path.
    pub fn new(path: &str) -> Result<Self, RocksDbError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Self { db })
    }

    /// Save consensus state (finalized block, validator registry, etc.)
    pub fn save_consensus_state(&self, state: &ConsensusState) -> Result<(), RocksDbError> {
        let data = bincode::serialize(state).map_err(|e| RocksDbError::new(e.to_string()))?;
        self.db.put(b"consensus_state", data)?;
        Ok(())
    }

    /// Load consensus state from RocksDB.
    pub fn load_consensus_state(&self) -> Result<ConsensusState, RocksDbError> {
        let data = self.db.get(b"consensus_state")?.ok_or_else(|| RocksDbError::new("No consensus state found"))?;
        let state: ConsensusState = bincode::deserialize(&data).map_err(|e| RocksDbError::new(e.to_string()))?;
        Ok(state)
    }

    /// Save state trie (account balances, contracts, etc.)
    pub fn save_state_trie(&self, trie: &StateTrie) -> Result<(), RocksDbError> {
        let data = bincode::serialize(trie).map_err(|e| RocksDbError::new(e.to_string()))?;
        self.db.put(b"state_trie", data)?;
        Ok(())
    }

    /// Load state trie from RocksDB.
    pub fn load_state_trie(&self) -> Result<StateTrie, RocksDbError> {
        let data = self.db.get(b"state_trie")?.ok_or_else(|| RocksDbError::new("No state trie found"))?;
        let trie: StateTrie = bincode::deserialize(&data).map_err(|e| RocksDbError::new(e.to_string()))?;
        Ok(trie)
    }

    /// Save pending transactions (mempool)
    pub fn save_pending_transactions(&self, txs: &[Transaction]) -> Result<(), RocksDbError> {
        let data = bincode::serialize(txs).map_err(|e| RocksDbError::new(e.to_string()))?;
        self.db.put(b"pending_txs", data)?;
        Ok(())
    }

    /// Load pending transactions from RocksDB.
    pub fn load_pending_transactions(&self) -> Result<Vec<Transaction>, RocksDbError> {
        let data = self.db.get(b"pending_txs")?.ok_or_else(|| RocksDbError::new("No pending transactions found"))?;
        let txs: Vec<Transaction> = bincode::deserialize(&data).map_err(|e| RocksDbError::new(e.to_string()))?;
        Ok(txs)
    }

    /// Create a snapshot (backup) of the current database at the given path.
    pub fn snapshot(&self, path: &str) -> Result<(), RocksDbError> {
        let checkpoint = Checkpoint::new(&self.db)?;
        checkpoint.create_checkpoint(path)?;
        Ok(())
    }

    /// Restore the database from a snapshot at the given path.
    pub fn restore_from_snapshot(&self, path: &str) -> Result<(), RocksDbError> {
        // This is a placeholder; actual restore logic may require DB re-initialization.
        // In production, you may want to close the DB, copy files, and reopen.
        Err(RocksDbError::new("Restore from snapshot not implemented: requires DB re-initialization"))
    }
} 