# POAR Crypto Integration Guide

This document provides concrete, actionable coding guidance for integrating cryptographic primitives in the POAR blockchain project. Each section corresponds to a key architectural recommendation, with practical Rust implementation advice and integration tips.

---

## 1. Centralized Crypto API Usage

**Recommendation:** All upper layers (consensus, storage, api, wallet) should access cryptography only via `src/crypto/mod.rs`.

**How to Code:**

- Export all crypto primitives in `mod.rs`:
  ```rust
  pub mod hash;
  pub mod signature;
  pub mod zk_proof;
  // ...
  pub use hash::*;
  pub use signature::*;
  pub use zk_proof::*;
  // ...
  ```
- In upper layers, always use:
  ```rust
  use crate::crypto::*;
  // or specific:
  use crate::crypto::{poseidon_hash, generate_groth16_proof};
  ```
- Never import submodules directly in upper layers.

---

## 2. ZK Proofs for Block and Transaction Validity

**Recommendation:** ZK proofs must be used for block and transaction validity.

**How to Code:**

- Define circuits for block and transaction validity in `src/consensus/circuits/`.
- Use `CircuitId::BlockValidity` and `CircuitId::TransactionValidity` enums in proof generation:
  ```rust
  let proof = generate_groth16_proof(circuit, pk, &public_inputs, &mut rng, CircuitId::BlockValidity)?;
  ```
- Integrate proof verification in block/tx validation logic:
  ```rust
  if !verify_groth16_proof(&zk_proof, vk, &public_inputs)? {
      return Err(ConsensusError::InvalidProof);
  }
  ```

---

## 3. Use Only Poseidon for On-Chain Hashing

**Recommendation:** Use Poseidon for all on-chain hashes; SHA256 only for external compatibility.

**How to Code:**

- In `src/crypto/hash.rs`, expose only Poseidon-based functions for Merkle roots, state roots, etc.:
  ```rust
  pub fn poseidon_hash(data: &[u8]) -> Vec<u8> { ... }
  pub fn merkle_root(leaves: &[Fr]) -> Fr { ... }
  ```
- If SHA256 is needed, gate it behind a feature flag:
  ```rust
  #[cfg(feature = "sha2")]
  pub fn sha256_hash(data: &[u8]) -> Vec<u8> { ... }
  ```

---

## 4. Encrypted Key Storage and Central KeyManager

**Recommendation:** Store all keys encrypted on disk; manage via a central KeyManager.

**How to Code:**

- Implement a `KeyManager` struct in `src/wallet/key_storage.rs`:
  ```rust
  pub struct KeyManager { ... }
  impl KeyManager {
      pub fn store_key(&self, key_id: &str, key: &[u8], password: &str) { ... }
      pub fn load_key(&self, key_id: &str, password: &str) -> Result<Vec<u8>, Error> { ... }
  }
  ```
- Use strong encryption (e.g., AES-GCM) for file storage.
- Never keep private keys in memory longer than necessary.

---

## 5. Secure Trusted Setup Parameter Management (UPDATED)

Groth16 parameters (proving/verifying keys) are now securely saved and loaded from disk for each circuit type. This ensures that the trusted setup is performed only once in a secure environment, and the resulting parameters are reused by all nodes.

**How to Use:**

```rust
// Save parameters after trusted setup
generate_keys_and_save() {
    let (pk, vk) = Groth16::<Bls12_381, LibsnarkReduction>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    TrustedSetupManager::save_setup(CircuitId::BlockValidity, &pk, &vk, "./params").unwrap();
}

// Load parameters for proof generation/verification
let (pk, vk) = TrustedSetupManager::load_setup(CircuitId::BlockValidity, "./params").unwrap();
```

- Parameters are stored as compressed binary files, one per circuit type.
- Always run the trusted setup in a secure, air-gapped environment.
- Never share the toxic waste (randomness) used during setup.

---

## 6. SIMD and CPU Cache Optimization

**Recommendation:** Enable SIMD and CPU cache optimizations for ZK and hash operations.

**How to Code:**

- Use Rust's `#[cfg(target_feature = "simd")]` or crates like `packed_simd` for SIMD code paths.
- Profile and optimize critical loops in Poseidon and proof generation.
- Example:
  ```rust
  #[cfg(target_feature = "avx2")]
  fn optimized_hash(inputs: &[Fr]) -> Fr { ... }
  ```
- Use `cargo bench` and flamegraph for performance tuning.

---

## 7. Integration and CI Testing

**Recommendation:** Write both unit and integration tests; run in CI.

**How to Code:**

- Place unit tests in each crypto module with `#[cfg(test)]`.
- Write integration tests in `tests/integration/` that use the public API:
  ```rust
  #[test]
  fn test_block_proof_verification() { ... }
  ```
- Add CI config (e.g., GitHub Actions) to run `cargo test --all` on every push.

---

## 8. Real Circuits for Production and Testing

**Recommendation:** Define real circuits (not just dummy) for production and test use.

**How to Code:**

- Implement circuits in `src/consensus/circuits/`:
  ```rust
  pub struct BlockValidityCircuit { ... }
  impl ConstraintSynthesizer<Fr> for BlockValidityCircuit { ... }
  ```
- Use these circuits in both tests and production proof generation.

---

## 9. Hex String Output for All Crypto Data

**Recommendation:** Output all proofs, hashes, and signatures as hex strings.

**How to Code:**

- Use `hex` crate for conversion:
  ```rust
  let hex_str = hex::encode(&proof_bytes);
  ```
- In API responses, always return hex strings for cryptographic data.

---

## 10. JSON API and External Compatibility

**Recommendation:** Use JSON APIs and hex/base64 for external integration.

**How to Code:**

- Define API structs with hex/base64 fields:
  ```rust
  #[derive(Serialize, Deserialize)]
  pub struct ProofResponse {
      pub proof: String, // hex
      pub public_inputs: String, // hex
  }
  ```
- Use `serde` for (de)serialization.
- Document API formats clearly.

---

## 11. Modular, Trait-Based Crypto Design

**Recommendation:** Use traits and modular design for extensibility.

**How to Code:**

- Define traits for hash, signature, and proof systems:
  ```rust
  pub trait ZkProofSystem {
      fn prove(...);
      fn verify(...);
  }
  ```
- Implement these traits for each algorithm (Groth16, PLONK, etc.).
- Use enums or trait objects for runtime selection if needed.

---

## 12. no_std and WASM Compatibility

**Recommendation:** Write all crypto code to be no_std and WASM compatible.

**How to Code:**

- Avoid using `std` directly; use `ark-std` and `alloc` where possible.
- Add `#![no_std]` to crypto modules if feasible.
- Test WASM builds with:
  ```sh
  cargo build --target wasm32-unknown-unknown
  ```
- Use feature flags to separate std and no_std code paths if needed.

---

_This guide ensures that POAR's cryptographic infrastructure is robust, maintainable, and ready for both current and future blockchain requirements._
