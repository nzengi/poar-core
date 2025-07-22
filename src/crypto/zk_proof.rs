use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::Rng;
use crate::types::proof::{ZKProof, ProofSystem, CircuitId};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};
use ark_ff::BigInteger;
use ark_r1cs_std::eq::EqGadget;

#[derive(Debug)]
pub enum ZkProofError {
    ProofGenerationError(String),
    ProofVerificationError(String),
    SerializationError(String),
    UnsupportedSystem,
}

pub fn generate_groth16_proof<C: ConstraintSynthesizer<ark_bls12_381::Fr>, R: Rng>(
    circuit: C,
    pk: &ProvingKey<Bls12_381>,
    public_inputs: &[ark_bls12_381::Fr],
    rng: &mut R,
    circuit_id: CircuitId,
) -> Result<ZKProof, ZkProofError> {
    let proof = Groth16::<Bls12_381, LibsnarkReduction>::create_random_proof_with_reduction(circuit, pk, rng)
        .map_err(|e| ZkProofError::ProofGenerationError(format!("Groth16 proof error: {e}")))?;
    let mut proof_bytes = Vec::new();
    proof.serialize_with_mode(&mut proof_bytes, Compress::Yes)
        .map_err(|e| ZkProofError::SerializationError(format!("Proof serialize: {e}")))?;
    let mut pub_inputs_bytes = Vec::new();
    for inp in public_inputs {
        pub_inputs_bytes.extend_from_slice(&inp.into_bigint().to_bytes_le());
    }
    Ok(ZKProof {
        system: ProofSystem::Groth16,
        proof_data: proof_bytes,
        public_inputs: pub_inputs_bytes,
        circuit_id,
        timestamp: chrono::Utc::now().timestamp() as u64,
    })
}

pub fn verify_groth16_proof(
    zk_proof: &ZKProof,
    vk: &VerifyingKey<Bls12_381>,
    public_inputs: &[ark_bls12_381::Fr],
) -> Result<bool, ZkProofError> {
    if zk_proof.system != ProofSystem::Groth16 {
        return Err(ZkProofError::UnsupportedSystem);
    }
    let mut proof_bytes_slice = &zk_proof.proof_data[..];
    let proof = <Proof<Bls12_381> as CanonicalDeserialize>::deserialize_with_mode(&mut proof_bytes_slice, Compress::Yes, Validate::No)
        .map_err(|e| ZkProofError::SerializationError(format!("Deserialize: {e}")))?;
    let pvk = prepare_verifying_key(vk);
    Groth16::<Bls12_381, LibsnarkReduction>::verify_proof(&pvk, &proof, public_inputs)
        .map_err(|e| ZkProofError::ProofVerificationError(format!("Verify: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::test_rng;

    // Basit bir circuit: x + y = z
    #[derive(Clone)]
    struct DummyCircuit {
        pub x: Fr,
        pub y: Fr,
        pub z: Fr,
    }
    impl ConstraintSynthesizer<Fr> for DummyCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            use ark_r1cs_std::alloc::AllocVar;
            use ark_r1cs_std::fields::fp::FpVar;
            let x_var = FpVar::new_input(cs.clone(), || Ok(self.x))?;
            let y_var = FpVar::new_input(cs.clone(), || Ok(self.y))?;
            let z_var = FpVar::new_input(cs.clone(), || Ok(self.z))?;
            (x_var + y_var).enforce_equal(&z_var)?;
            Ok(())
        }
    }

    #[test]
    fn test_groth16_proof_positive() {
        let mut rng = test_rng();
        let x = Fr::from(3u64);
        let y = Fr::from(4u64);
        let z = Fr::from(7u64);
        let circuit = DummyCircuit { x, y, z };
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        // Setup
        let params = Groth16::<Bls12_381, LibsnarkReduction>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng).unwrap();
        let pk = &params;
        let vk = &params.vk;
        let public_inputs = [x, y, z];
        // Proof
        let proof = super::generate_groth16_proof(circuit, pk, &public_inputs, &mut rng, CircuitId::BlockValidity).unwrap();
        // Verify
        let result = super::verify_groth16_proof(&proof, vk, &public_inputs).unwrap();
        assert!(result);
    }

    #[test]
    fn test_groth16_proof_negative_wrong_input() {
        let mut rng = test_rng();
        let x = Fr::from(3u64);
        let y = Fr::from(4u64);
        let z = Fr::from(7u64);
        let circuit = DummyCircuit { x, y, z };
        let params = Groth16::<Bls12_381, LibsnarkReduction>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng).unwrap();
        let pk = &params;
        let vk = &params.vk;
        let public_inputs = [x, y, z];
        let proof = super::generate_groth16_proof(circuit, pk, &public_inputs, &mut rng, CircuitId::BlockValidity).unwrap();
        // Yanlış public input ile doğrulama
        let wrong_inputs = [x, y, Fr::from(8u64)];
        let result = super::verify_groth16_proof(&proof, vk, &wrong_inputs).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_groth16_proof_serialization() {
        let mut rng = test_rng();
        let x = Fr::from(2u64);
        let y = Fr::from(5u64);
        let z = Fr::from(7u64);
        let circuit = DummyCircuit { x, y, z };
        let params = Groth16::<Bls12_381, LibsnarkReduction>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng).unwrap();
        let pk = &params;
        let vk = &params.vk;
        let public_inputs = [x, y, z];
        let proof = super::generate_groth16_proof(circuit, pk, &public_inputs, &mut rng, CircuitId::MerkleInclusion).unwrap();
        // Serialize/deserialize
        let serialized = bincode::serialize(&proof).unwrap();
        let deserialized: super::ZKProof = bincode::deserialize(&serialized).unwrap();
        let result = super::verify_groth16_proof(&deserialized, vk, &public_inputs).unwrap();
        assert!(result);
    }
}
