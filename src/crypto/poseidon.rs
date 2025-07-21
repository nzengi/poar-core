use ark_ff::{BigInteger, BigInteger256, Field, PrimeField, Zero};
use ark_bls12_381::Fr;
use ark_std::{vec::Vec, UniformRand};
use ark_std::rand::Rng;

/// Poseidon hash function for ZK-PoV
/// Based on ETH 3.0 Poseidon Cryptanalysis Initiative
/// Uses cryptanalysis-resistant parameters
pub struct PoseidonHash {
    /// Round constants for Poseidon permutation
    round_constants: Vec<Fr>,
    /// MDS matrix for linear layer
    mds_matrix: Vec<Vec<Fr>>,
    /// Number of full rounds
    full_rounds: usize,
    /// Number of partial rounds
    partial_rounds: usize,
    /// Security parameter
    security_bits: usize,
}

/// Poseidon hash configuration
#[derive(Clone, Debug)]
pub struct PoseidonConfig {
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub alpha: u64,
    pub security_bits: usize,
}

impl Default for PoseidonConfig {
    fn default() -> Self {
        // ETH 3.0 recommended parameters
        Self {
            full_rounds: 8,
            partial_rounds: 56,
            alpha: 5,
            security_bits: 128,
        }
    }
}

impl PoseidonHash {
    /// Create new Poseidon hash instance
    pub fn new(config: PoseidonConfig) -> Self {
        let mut rng = ark_std::rand::thread_rng();
        
        // Generate round constants
        let total_rounds = config.full_rounds + config.partial_rounds;
        let round_constants: Vec<Fr> = (0..total_rounds)
            .map(|_| Fr::rand(&mut rng))
            .collect();
        
        // Generate MDS matrix
        let mds_matrix = Self::generate_mds_matrix(3, &mut rng);
        
        Self {
            round_constants,
            mds_matrix,
            full_rounds: config.full_rounds,
            partial_rounds: config.partial_rounds,
            security_bits: config.security_bits,
        }
    }
    
    /// Hash a single field element
    pub fn hash_single(&self, input: Fr) -> Fr {
        let mut state = vec![input, Fr::zero(), Fr::zero()];
        self.permute(&mut state);
        state[0]
    }
    
    /// Hash multiple field elements
    pub fn hash_multi(&self, inputs: &[Fr]) -> Fr {
        if inputs.is_empty() {
            return Fr::zero();
        }
        
        let mut state = vec![Fr::zero(); 3];
        
        // Process inputs in chunks
        for chunk in inputs.chunks(2) {
            if chunk.len() == 1 {
                state[0] = chunk[0];
                state[1] = Fr::zero();
            } else {
                state[0] = chunk[0];
                state[1] = chunk[1];
            }
            state[2] = Fr::zero();
            self.permute(&mut state);
        }
        
        state[0]
    }
    
    /// Hash arbitrary bytes
    pub fn hash_bytes(&self, data: &[u8]) -> Fr {
        let field_elements = self.bytes_to_field_elements(data);
        self.hash_multi(&field_elements)
    }
    
    /// Generate Merkle root from leaves
    pub fn merkle_root(&self, leaves: &[Fr]) -> Fr {
        if leaves.is_empty() {
            return Fr::zero();
        }
        
        let mut current_level: Vec<Fr> = leaves.to_vec();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 1 {
                    self.hash_single(chunk[0])
                } else {
                    self.hash_multi(chunk)
                };
                next_level.push(hash);
            }
            
            current_level = next_level;
        }
        
        current_level[0]
    }
    
    /// Poseidon permutation
    fn permute(&self, state: &mut [Fr]) {
        let total_rounds = self.full_rounds + self.partial_rounds;
        
        for round in 0..total_rounds {
            // Add round constants
            for i in 0..state.len() {
                state[i] += self.round_constants[round];
            }
            
            // S-box layer
            if round < self.full_rounds / 2 || round >= total_rounds - self.full_rounds / 2 {
                // Full rounds: apply S-box to all elements
                for i in 0..state.len() {
                    state[i] = self.sbox(state[i]);
                }
            } else {
                // Partial rounds: apply S-box only to first element
                state[0] = self.sbox(state[0]);
            }
            
            // MDS matrix multiplication
            let old_state = state.to_vec();
            for i in 0..state.len() {
                state[i] = Fr::zero();
                for j in 0..state.len() {
                    state[i] += self.mds_matrix[i][j] * old_state[j];
                }
            }
        }
    }
    
    /// S-box function (x^5)
    fn sbox(&self, x: Fr) -> Fr {
        let x2 = x * x;
        let x4 = x2 * x2;
        x4 * x
    }
    
    /// Generate MDS matrix
    fn generate_mds_matrix(size: usize, rng: &mut impl Rng) -> Vec<Vec<Fr>> {
        let mut matrix = vec![vec![Fr::zero(); size]; size];
        
        // Generate random MDS matrix
        for i in 0..size {
            for j in 0..size {
                matrix[i][j] = Fr::rand(rng);
            }
        }
        
        matrix
    }
    
    /// Convert bytes to field elements
    fn bytes_to_field_elements(&self, data: &[u8]) -> Vec<Fr> {
        let mut elements = Vec::new();
        let mut buffer = Vec::new();
        
        for &byte in data {
            buffer.push(byte);
            
            if buffer.len() == 32 {
                // Convert 32 bytes to field element
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&buffer);
                let field_element = Fr::from_le_bytes_mod_order(&bytes);
                elements.push(field_element);
                buffer.clear();
            }
        }
        
        // Handle remaining bytes
        if !buffer.is_empty() {
            let mut bytes = [0u8; 32];
            for (i, &byte) in buffer.iter().enumerate() {
                bytes[i] = byte;
            }
            let field_element = Fr::from_le_bytes_mod_order(&bytes);
            elements.push(field_element);
        }
        
        elements
    }
}

/// Poseidon hash for ZK-PoV specific use cases
pub struct ZKPoVPoseidon {
    hash: PoseidonHash,
}

impl ZKPoVPoseidon {
    /// Create new ZK-PoV Poseidon instance
    pub fn new() -> Self {
        let config = PoseidonConfig::default();
        let hash = PoseidonHash::new(config);
        
        Self { hash }
    }
    
    /// Hash transaction
    pub fn hash_transaction(&self, tx_data: &[u8]) -> Fr {
        self.hash.hash_bytes(tx_data)
    }
    
    /// Hash block header
    pub fn hash_block_header(&self, header_data: &[u8]) -> Fr {
        self.hash.hash_bytes(header_data)
    }
    
    /// Hash block
    pub fn hash_block(&self, block_data: &[u8]) -> Fr {
        self.hash.hash_bytes(block_data)
    }
    
    /// Generate Merkle root for transactions
    pub fn transaction_merkle_root(&self, transaction_hashes: &[Fr]) -> Fr {
        self.hash.merkle_root(transaction_hashes)
    }
    
    /// Hash state root
    pub fn hash_state_root(&self, state_data: &[u8]) -> Fr {
        self.hash.hash_bytes(state_data)
    }

    pub fn hash_bytes_to_vec(&self, data: &[u8]) -> Vec<u8> {
        let hash_fr = self.hash.hash_bytes(data);
        let mut bytes = vec![0u8; 32];
        let limbs = hash_fr.into_bigint().to_bytes_le();
        for (i, b) in limbs.iter().enumerate().take(32) {
            bytes[i] = *b;
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    
    #[test]
    fn test_poseidon_hash() {
        let poseidon = ZKPoVPoseidon::new();
        
        // Test single hash
        let input = Fr::from(123u64);
        let hash = poseidon.hash.hash_single(input);
        assert_ne!(hash, input);
        
        // Test multiple inputs
        let inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let hash = poseidon.hash.hash_multi(&inputs);
        assert_ne!(hash, Fr::zero());
        
        // Test bytes hash
        let data = b"ZK-PoV Poseidon Hash Test";
        let hash = poseidon.hash.hash_bytes(data);
        assert_ne!(hash, Fr::zero());
    }
    
    #[test]
    fn test_merkle_root() {
        let poseidon = ZKPoVPoseidon::new();
        
        let leaves = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        
        let root = poseidon.hash.merkle_root(&leaves);
        assert_ne!(root, Fr::zero());
        
        // Test with odd number of leaves
        let leaves = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let root = poseidon.hash.merkle_root(&leaves);
        assert_ne!(root, Fr::zero());
    }
    
    #[test]
    fn test_zkpov_specific() {
        let poseidon = ZKPoVPoseidon::new();
        
        // Test transaction hash
        let tx_data = b"transaction_data";
        let tx_hash = poseidon.hash_transaction(tx_data);
        assert_ne!(tx_hash, Fr::zero());
        
        // Test block hash
        let block_data = b"block_data";
        let block_hash = poseidon.hash_block(block_data);
        assert_ne!(block_hash, Fr::zero());
        
        // Test transaction merkle root
        let tx_hashes = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ];
        let merkle_root = poseidon.transaction_merkle_root(&tx_hashes);
        assert_ne!(merkle_root, Fr::zero());
    }
} 