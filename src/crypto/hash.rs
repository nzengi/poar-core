use crate::crypto::poseidon::ZKPoVPoseidon;
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Hash arbitrary bytes using Poseidon (ZK-friendly, returns Vec<u8>)
pub fn poseidon_hash(data: &[u8]) -> Vec<u8> {
    let poseidon = ZKPoVPoseidon::new();
    poseidon.hash_bytes_to_vec(data)
}

/// Hash arbitrary bytes and return field element (for ZK circuits)
pub fn poseidon_hash_fr(data: &[u8]) -> Fr {
    let poseidon = ZKPoVPoseidon::new();
    poseidon.hash_transaction(data)
}

/// Compute Merkle root from leaf hashes (as Fr)
pub fn merkle_root(leaves: &[Fr]) -> Fr {
    let poseidon = ZKPoVPoseidon::new();
    poseidon.transaction_merkle_root(leaves)
}

/// Hash transaction data (for tx id, returns Vec<u8>)
pub fn hash_transaction(tx_data: &[u8]) -> Vec<u8> {
    let poseidon = ZKPoVPoseidon::new();
    poseidon.hash_transaction(tx_data).into_bigint().to_bytes_le()
}

/// Hash block header data (returns Vec<u8>)
pub fn hash_block_header(header_data: &[u8]) -> Vec<u8> {
    let poseidon = ZKPoVPoseidon::new();
    poseidon.hash_block_header(header_data).into_bigint().to_bytes_le()
}

/// Hash state root data (returns Vec<u8>)
pub fn hash_state_root(state_data: &[u8]) -> Vec<u8> {
    let poseidon = ZKPoVPoseidon::new();
    poseidon.hash_state_root(state_data).into_bigint().to_bytes_le()
}

/// (Optional) SHA256 hash for compatibility (returns Vec<u8>)
#[cfg(feature = "sha2")] // Enable with --features sha2
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
