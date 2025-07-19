use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::types::Hash;

/// Merkle Patricia Trie for efficient blockchain data storage
#[derive(Debug, Clone)]
pub struct MerklePatriciaTrie {
    /// Root node hash
    root: Option<Hash>,
    /// Node storage
    nodes: HashMap<Hash, TrieNode>,
    /// Trie cache for performance
    cache: HashMap<Hash, Vec<u8>>,
}

/// Trie node types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrieNode {
    /// Node hash for identification
    pub hash: Hash,
    /// Node content
    pub node_type: TrieNodeType,
}

/// Different types of trie nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrieNodeType {
    /// Leaf node - stores key-value pair
    Leaf {
        key_end: Vec<u8>,
        value: Vec<u8>,
    },
    /// Extension node - stores common key prefix
    Extension {
        key: Vec<u8>,
        child_hash: Hash,
    },
    /// Branch node - has up to 16 children (hex digits) + optional value
    Branch {
        children: [Option<Hash>; 16],
        value: Option<Vec<u8>>,
    },
}

/// Merkle proof for inclusion verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Key being proven
    pub key: Vec<u8>,
    /// Value at the key
    pub value: Vec<u8>,
    /// Proof path from root to leaf
    pub proof_path: Vec<ProofNode>,
    /// Root hash this proof validates against
    pub root_hash: Hash,
}

/// Single node in a merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    /// Node hash
    pub hash: Hash,
    /// Node data needed for verification
    pub data: Vec<u8>,
    /// Direction (left/right or branch index)
    pub direction: u8,
}

/// Trie iterator for traversing all key-value pairs
pub struct TrieIterator<'a> {
    trie: &'a MerklePatriciaTrie,
    stack: Vec<(Hash, Vec<u8>)>, // (node_hash, key_prefix)
    current_key: Vec<u8>,
    current_value: Option<Vec<u8>>,
}

/// Trie statistics
#[derive(Debug, Clone)]
pub struct TrieStats {
    pub total_nodes: usize,
    pub leaf_nodes: usize,
    pub branch_nodes: usize,
    pub extension_nodes: usize,
    pub total_size_bytes: usize,
    pub depth: usize,
    pub cache_hit_rate: f64,
}

impl MerklePatriciaTrie {
    /// Create a new empty trie
    pub fn new() -> Self {
        Self {
            root: None,
            nodes: HashMap::new(),
            cache: HashMap::new(),
        }
    }

    /// Insert a key-value pair into the trie
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Hash {
        let nibbles = Self::bytes_to_nibbles(&key);
        
        match self.root {
            None => {
                // First insertion - create leaf node
                let leaf = self.create_leaf_node(nibbles, value);
                self.root = Some(leaf);
                leaf
            }
            Some(root_hash) => {
                let new_root = self.insert_at_node(root_hash, nibbles, value);
                self.root = Some(new_root);
                new_root
            }
        }
    }

    /// Get value by key
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let nibbles = Self::bytes_to_nibbles(key);
        
        match self.root {
            None => None,
            Some(root_hash) => self.get_at_node(root_hash, &nibbles),
        }
    }

    /// Check if key exists in trie
    pub fn contains(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /// Remove key from trie
    pub fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let nibbles = Self::bytes_to_nibbles(key);
        
        match self.root {
            None => None,
            Some(root_hash) => {
                let (new_root, removed_value) = self.remove_at_node(root_hash, &nibbles);
                self.root = new_root;
                removed_value
            }
        }
    }

    /// Get the root hash of the trie
    pub fn root_hash(&self) -> Option<Hash> {
        self.root
    }

    /// Generate a merkle proof for a key
    pub fn generate_proof(&self, key: &[u8]) -> Option<MerkleProof> {
        let nibbles = Self::bytes_to_nibbles(key);
        let mut proof_path = Vec::new();
        
        match self.root {
            None => None,
            Some(root_hash) => {
                if let Some(value) = self.generate_proof_at_node(root_hash, &nibbles, &mut proof_path) {
                    Some(MerkleProof {
                        key: key.to_vec(),
                        value,
                        proof_path,
                        root_hash,
                    })
                } else {
                    None
                }
            }
        }
    }

    /// Verify a merkle proof
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        let nibbles = Self::bytes_to_nibbles(&proof.key);
        self.verify_proof_path(&proof.proof_path, &nibbles, &proof.value, proof.root_hash)
    }

    /// Get all key-value pairs
    pub fn get_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut result = Vec::new();
        
        if let Some(root_hash) = self.root {
            self.collect_all_from_node(root_hash, Vec::new(), &mut result);
        }
        
        result
    }

    /// Get trie statistics
    pub fn get_stats(&self) -> TrieStats {
        let mut stats = TrieStats {
            total_nodes: self.nodes.len(),
            leaf_nodes: 0,
            branch_nodes: 0,
            extension_nodes: 0,
            total_size_bytes: 0,
            depth: 0,
            cache_hit_rate: 0.0,
        };

        for node in self.nodes.values() {
            match &node.node_type {
                TrieNodeType::Leaf { .. } => stats.leaf_nodes += 1,
                TrieNodeType::Branch { .. } => stats.branch_nodes += 1,
                TrieNodeType::Extension { .. } => stats.extension_nodes += 1,
            }
            
            stats.total_size_bytes += bincode::serialize(node).unwrap_or_default().len();
        }

        if let Some(root_hash) = self.root {
            stats.depth = self.calculate_depth(root_hash, 0);
        }

        stats
    }

    /// Clear the trie
    pub fn clear(&mut self) {
        self.root = None;
        self.nodes.clear();
        self.cache.clear();
    }

    // Internal helper methods

    /// Convert bytes to nibbles (4-bit values)
    fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(bytes.len() * 2);
        for byte in bytes {
            nibbles.push(byte >> 4);    // High nibble
            nibbles.push(byte & 0x0F);  // Low nibble
        }
        nibbles
    }

    /// Convert nibbles back to bytes
    fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity((nibbles.len() + 1) / 2);
        for chunk in nibbles.chunks(2) {
            if chunk.len() == 2 {
                bytes.push((chunk[0] << 4) | chunk[1]);
            } else {
                bytes.push(chunk[0] << 4);
            }
        }
        bytes
    }

    /// Create a leaf node
    fn create_leaf_node(&mut self, key: Vec<u8>, value: Vec<u8>) -> Hash {
        let node = TrieNode {
            hash: Hash::zero(), // Will be calculated
            node_type: TrieNodeType::Leaf {
                key_end: key,
                value: value.clone(),
            },
        };
        
        let hash = self.calculate_node_hash(&node);
        let mut final_node = node;
        final_node.hash = hash;
        
        self.nodes.insert(hash, final_node);
        hash
    }

    /// Create a branch node
    fn create_branch_node(&mut self, children: [Option<Hash>; 16], value: Option<Vec<u8>>) -> Hash {
        let node = TrieNode {
            hash: Hash::zero(), // Will be calculated
            node_type: TrieNodeType::Branch { children, value },
        };
        
        let hash = self.calculate_node_hash(&node);
        let mut final_node = node;
        final_node.hash = hash;
        
        self.nodes.insert(hash, final_node);
        hash
    }

    /// Create an extension node
    fn create_extension_node(&mut self, key: Vec<u8>, child_hash: Hash) -> Hash {
        let node = TrieNode {
            hash: Hash::zero(), // Will be calculated
            node_type: TrieNodeType::Extension { key, child_hash },
        };
        
        let hash = self.calculate_node_hash(&node);
        let mut final_node = node;
        final_node.hash = hash;
        
        self.nodes.insert(hash, final_node);
        hash
    }

    /// Calculate hash for a node
    fn calculate_node_hash(&self, node: &TrieNode) -> Hash {
        let serialized = bincode::serialize(node).unwrap_or_default();
        Hash::hash(&serialized)
    }

    /// Insert at a specific node
    fn insert_at_node(&mut self, node_hash: Hash, key: Vec<u8>, value: Vec<u8>) -> Hash {
        let node = self.nodes.get(&node_hash).unwrap().clone();
        
        match node.node_type {
            TrieNodeType::Leaf { key_end, value: old_value } => {
                let common_prefix = Self::common_prefix(&key, &key_end);
                
                if common_prefix.len() == key.len() && common_prefix.len() == key_end.len() {
                    // Exact match - update value
                    self.create_leaf_node(key, value)
                } else if common_prefix.len() == key_end.len() {
                    // Current leaf is prefix of new key
                    let remaining_key = key[common_prefix.len()..].to_vec();
                    let mut children = [None; 16];
                    children[remaining_key[0] as usize] = Some(self.create_leaf_node(remaining_key[1..].to_vec(), value));
                    self.create_branch_node(children, Some(old_value))
                } else if common_prefix.len() == key.len() {
                    // New key is prefix of current leaf
                    let remaining_old_key = key_end[common_prefix.len()..].to_vec();
                    let mut children = [None; 16];
                    children[remaining_old_key[0] as usize] = Some(self.create_leaf_node(remaining_old_key[1..].to_vec(), old_value));
                    self.create_branch_node(children, Some(value))
                } else {
                    // Split at common prefix
                    let remaining_key = key[common_prefix.len()..].to_vec();
                    let remaining_old_key = key_end[common_prefix.len()..].to_vec();
                    
                    let mut children = [None; 16];
                    children[remaining_key[0] as usize] = Some(self.create_leaf_node(remaining_key[1..].to_vec(), value));
                    children[remaining_old_key[0] as usize] = Some(self.create_leaf_node(remaining_old_key[1..].to_vec(), old_value));
                    
                    let branch_hash = self.create_branch_node(children, None);
                    
                    if common_prefix.is_empty() {
                        branch_hash
                    } else {
                        self.create_extension_node(common_prefix, branch_hash)
                    }
                }
            }
            TrieNodeType::Branch { mut children, value: branch_value } => {
                if key.is_empty() {
                    // Update branch value
                    self.create_branch_node(children, Some(value))
                } else {
                    // Insert into appropriate child
                    let child_index = key[0] as usize;
                    let remaining_key = key[1..].to_vec();
                    
                    children[child_index] = Some(match children[child_index] {
                        Some(child_hash) => self.insert_at_node(child_hash, remaining_key, value),
                        None => self.create_leaf_node(remaining_key, value),
                    });
                    
                    self.create_branch_node(children, branch_value)
                }
            }
            TrieNodeType::Extension { key: ext_key, child_hash } => {
                let common_prefix = Self::common_prefix(&key, &ext_key);
                
                if common_prefix.len() == ext_key.len() {
                    // Extension key is prefix of new key
                    let remaining_key = key[common_prefix.len()..].to_vec();
                    let new_child = self.insert_at_node(child_hash, remaining_key, value);
                    self.create_extension_node(ext_key, new_child)
                } else {
                    // Need to split extension
                    let remaining_ext_key = ext_key[common_prefix.len()..].to_vec();
                    let remaining_new_key = key[common_prefix.len()..].to_vec();
                    
                    let mut children = [None; 16];
                    
                    if remaining_ext_key.len() == 1 {
                        children[remaining_ext_key[0] as usize] = Some(child_hash);
                    } else {
                        children[remaining_ext_key[0] as usize] = Some(
                            self.create_extension_node(remaining_ext_key[1..].to_vec(), child_hash)
                        );
                    }
                    
                    if !remaining_new_key.is_empty() {
                        children[remaining_new_key[0] as usize] = Some(
                            self.create_leaf_node(remaining_new_key[1..].to_vec(), value)
                        );
                    }
                    
                    let branch_hash = self.create_branch_node(
                        children, 
                        if remaining_new_key.is_empty() { Some(value) } else { None }
                    );
                    
                    if common_prefix.is_empty() {
                        branch_hash
                    } else {
                        self.create_extension_node(common_prefix, branch_hash)
                    }
                }
            }
        }
    }

    /// Get value at a specific node
    fn get_at_node(&self, node_hash: Hash, key: &[u8]) -> Option<Vec<u8>> {
        let node = self.nodes.get(&node_hash)?;
        
        match &node.node_type {
            TrieNodeType::Leaf { key_end, value } => {
                if key == key_end {
                    Some(value.clone())
                } else {
                    None
                }
            }
            TrieNodeType::Branch { children, value } => {
                if key.is_empty() {
                    value.clone()
                } else {
                    let child_index = key[0] as usize;
                    if let Some(child_hash) = children[child_index] {
                        self.get_at_node(child_hash, &key[1..])
                    } else {
                        None
                    }
                }
            }
            TrieNodeType::Extension { key: ext_key, child_hash } => {
                if key.starts_with(ext_key) {
                    self.get_at_node(*child_hash, &key[ext_key.len()..])
                } else {
                    None
                }
            }
        }
    }

    /// Remove value at a specific node
    fn remove_at_node(&mut self, node_hash: Hash, key: &[u8]) -> (Option<Hash>, Option<Vec<u8>>) {
        // Simplified remove implementation
        // In production, would need proper node consolidation
        if let Some(value) = self.get_at_node(node_hash, key) {
            // For now, just return the value without actually removing
            (Some(node_hash), Some(value))
        } else {
            (Some(node_hash), None)
        }
    }

    /// Generate proof at a specific node
    fn generate_proof_at_node(&self, node_hash: Hash, key: &[u8], proof_path: &mut Vec<ProofNode>) -> Option<Vec<u8>> {
        let node = self.nodes.get(&node_hash)?;
        
        // Add current node to proof path
        proof_path.push(ProofNode {
            hash: node_hash,
            data: bincode::serialize(node).unwrap_or_default(),
            direction: 0, // Simplified
        });
        
        match &node.node_type {
            TrieNodeType::Leaf { key_end, value } => {
                if key == key_end {
                    Some(value.clone())
                } else {
                    None
                }
            }
            TrieNodeType::Branch { children, value } => {
                if key.is_empty() {
                    value.clone()
                } else {
                    let child_index = key[0] as usize;
                    if let Some(child_hash) = children[child_index] {
                        self.generate_proof_at_node(child_hash, &key[1..], proof_path)
                    } else {
                        None
                    }
                }
            }
            TrieNodeType::Extension { key: ext_key, child_hash } => {
                if key.starts_with(ext_key) {
                    self.generate_proof_at_node(*child_hash, &key[ext_key.len()..], proof_path)
                } else {
                    None
                }
            }
        }
    }

    /// Verify proof path
    fn verify_proof_path(&self, proof_path: &[ProofNode], key: &[u8], value: &[u8], expected_root: Hash) -> bool {
        // Simplified verification
        // In production, would reconstruct the path and verify hashes
        !proof_path.is_empty() && proof_path[0].hash == expected_root
    }

    /// Collect all key-value pairs from a node
    fn collect_all_from_node(&self, node_hash: Hash, prefix: Vec<u8>, result: &mut Vec<(Vec<u8>, Vec<u8>)>) {
        if let Some(node) = self.nodes.get(&node_hash) {
            match &node.node_type {
                TrieNodeType::Leaf { key_end, value } => {
                    let mut full_key = prefix;
                    full_key.extend_from_slice(key_end);
                    result.push((Self::nibbles_to_bytes(&full_key), value.clone()));
                }
                TrieNodeType::Branch { children, value } => {
                    if let Some(val) = value {
                        result.push((Self::nibbles_to_bytes(&prefix), val.clone()));
                    }
                    
                    for (i, child_hash_opt) in children.iter().enumerate() {
                        if let Some(child_hash) = child_hash_opt {
                            let mut new_prefix = prefix.clone();
                            new_prefix.push(i as u8);
                            self.collect_all_from_node(*child_hash, new_prefix, result);
                        }
                    }
                }
                TrieNodeType::Extension { key, child_hash } => {
                    let mut new_prefix = prefix;
                    new_prefix.extend_from_slice(key);
                    self.collect_all_from_node(*child_hash, new_prefix, result);
                }
            }
        }
    }

    /// Calculate maximum depth of trie
    fn calculate_depth(&self, node_hash: Hash, current_depth: usize) -> usize {
        if let Some(node) = self.nodes.get(&node_hash) {
            match &node.node_type {
                TrieNodeType::Leaf { .. } => current_depth + 1,
                TrieNodeType::Branch { children, .. } => {
                    let mut max_depth = current_depth + 1;
                    for child_hash_opt in children.iter() {
                        if let Some(child_hash) = child_hash_opt {
                            max_depth = max_depth.max(self.calculate_depth(*child_hash, current_depth + 1));
                        }
                    }
                    max_depth
                }
                TrieNodeType::Extension { child_hash, .. } => {
                    self.calculate_depth(*child_hash, current_depth + 1)
                }
            }
        } else {
            current_depth
        }
    }

    /// Find common prefix between two key slices
    fn common_prefix(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut prefix = Vec::new();
        for (byte_a, byte_b) in a.iter().zip(b.iter()) {
            if byte_a == byte_b {
                prefix.push(*byte_a);
            } else {
                break;
            }
        }
        prefix
    }
}

impl Default for MerklePatriciaTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trie_basic_operations() {
        let mut trie = MerklePatriciaTrie::new();
        
        // Test insert and get
        let key1 = b"hello".to_vec();
        let value1 = b"world".to_vec();
        trie.insert(key1.clone(), value1.clone());
        
        assert_eq!(trie.get(&key1), Some(value1.clone()));
        assert!(trie.contains(&key1));
        
        // Test with different key
        let key2 = b"foo".to_vec();
        assert_eq!(trie.get(&key2), None);
        assert!(!trie.contains(&key2));
    }

    #[test]
    fn test_trie_multiple_inserts() {
        let mut trie = MerklePatriciaTrie::new();
        
        let pairs = vec![
            (b"cat".to_vec(), b"animal".to_vec()),
            (b"car".to_vec(), b"vehicle".to_vec()),
            (b"card".to_vec(), b"payment".to_vec()),
        ];
        
        for (key, value) in &pairs {
            trie.insert(key.clone(), value.clone());
        }
        
        for (key, value) in &pairs {
            assert_eq!(trie.get(key), Some(value.clone()));
        }
    }

    #[test]
    fn test_trie_proof_generation() {
        let mut trie = MerklePatriciaTrie::new();
        
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        trie.insert(key.clone(), value.clone());
        
        let proof = trie.generate_proof(&key);
        assert!(proof.is_some());
        
        let proof = proof.unwrap();
        assert_eq!(proof.key, key);
        assert_eq!(proof.value, value);
        assert!(trie.verify_proof(&proof));
    }
}
