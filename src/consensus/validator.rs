// POAR Consensus Validator - Placeholder
// TODO: Implement consensus validator functionality

use crate::types::token::{MIN_VALIDATOR_STAKE, VALIDATOR_STAKE_CAP, UNSTAKE_BONUS};
use crate::types::validator::ValidatorInfo; // Adjust import as needed
use crate::consensus::engine::ConsensusError; // Error type

/// Registers a new validator, enforcing minimum stake and stake cap
pub async fn register_validator_with_min_stake_and_cap(
    registry: &mut std::collections::HashMap<_, _>,
    info: ValidatorInfo,
    total_stake: u64,
) -> Result<(), ConsensusError> {
    if info.stake < MIN_VALIDATOR_STAKE {
        return Err(ConsensusError::InsufficientStake);
    }
    // Enforce validator stake cap (soft cap): if stake > 10% of total, return error
    if total_stake > 0 && (info.stake as f64) / (total_stake as f64) > VALIDATOR_STAKE_CAP {
        return Err(ConsensusError::StateError("Validator stake exceeds 10% soft cap".to_string()));
    }
    registry.insert(info.address, info);
    Ok(())
}

/// Applies unstake bonus if stake ratio is too high (circulation too low)
pub fn apply_unstake_bonus(amount: u64, stake_ratio: f64) -> u64 {
    // If stake ratio > 90%, apply +2% bonus to unstaking amount
    if stake_ratio > 0.9 {
        ((amount as f64) * (1.0 + UNSTAKE_BONUS)).round() as u64
    } else {
        amount
    }
}

// Placeholder implementation
