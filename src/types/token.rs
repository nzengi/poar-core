use serde::{Deserialize, Serialize};
use std::fmt;

// =============================
// POAR Token Economics Constants
// =============================

/// Initial supply minted at genesis
pub const INITIAL_SUPPLY: u64 = 10_000_000;

/// Maximum supply (hard cap)
pub const MAX_SUPPLY: u64 = 1_000_000_000;

/// Minimum supply (burn floor) – total supply cannot go below this
pub const MIN_SUPPLY: u64 = 100_000_000;

/// Initial epoch reward (decreases with decay)
pub const BASE_REWARD: u64 = 50_000;

/// Decay factor (each epoch reward is this fraction of the previous)
pub const DECAY_FACTOR: f64 = 0.99997;

/// Percentage of transaction fee that is burned (e.g., 0.20 = 20%)
pub const BURN_RATIO: f64 = 0.20;

/// Minimum stake required to become a validator
pub const MIN_VALIDATOR_STAKE: u64 = 50_000;

/// Early adopter bonus rate (first 2 years)
pub const EARLY_ADOPTER_BONUS: f64 = 0.10;

/// Early adopter bonus duration (in epochs, 2 years = 730 epochs)
pub const EARLY_ADOPTER_BONUS_EPOCHS: u64 = 730;

/// Stake multiplier for low stake ratio (<60%)
pub const LOW_STAKE_BONUS: f64 = 0.10; // +10%

/// Stake penalty for high stake ratio (>80%)
pub const HIGH_STAKE_PENALTY: f64 = -0.10; // -10%

/// Minimum transaction fee (in ZERO units, 0.01 POAR)
pub const FEE_MINIMUM: u64 = 10_000_000; // 0.01 * 1_000_000_000

/// Typical transfer fee range (in ZERO units, 0.01–0.05 POAR)
pub const FEE_TRANSFER_MIN: u64 = 10_000_000; // 0.01 POAR
pub const FEE_TRANSFER_MAX: u64 = 50_000_000; // 0.05 POAR

/// Soft cap for validator stake (no validator should control more than 10% of total stake)
pub const VALIDATOR_STAKE_CAP: f64 = 0.10;

/// Unstake bonus (+2% if circulation drops too low)
pub const UNSTAKE_BONUS: f64 = 0.02;

/// ZK-PoV Token Units
/// 
/// Token hierarchy:
/// 1 POAR = 1,000,000,000 PROOF
/// 1 PROOF = 1,000,000,000 VALID  
/// 1 VALID = 1,000,000,000 ZERO
/// 
/// Total: 27 decimals (3x9)

/// Main POAR token unit (1 POAR)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Poar(u128);

/// PROOF unit (1 POAR = 1,000,000,000 PROOF)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Proof(u128);

/// VALID unit (1 PROOF = 1,000,000,000 VALID)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Valid(u128);

/// ZERO unit (1 VALID = 1,000,000,000 ZERO)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Zero(u128);

/// Token conversion constants
pub const PROOF_PER_POAR: u128 = 1_000_000_000u128;
pub const VALID_PER_PROOF: u128 = 1_000_000_000u128;
pub const ZERO_PER_VALID: u128 = 1_000_000_000u128;
pub const ZERO_PER_POAR: u128 = PROOF_PER_POAR * VALID_PER_PROOF * ZERO_PER_VALID;

/// Token unit types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenUnit {
    Poar,
    Proof,
    Valid,
    Zero,
}

/// Token amount with unit specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAmount {
    pub amount: u128,
    pub unit: TokenUnit,
}

impl Poar {
    /// Create new POAR amount
    pub fn new(amount: u128) -> Self {
        Self(amount)
    }

    /// Convert to PROOF
    pub fn to_proof(&self) -> Proof {
        Proof(self.0 * PROOF_PER_POAR)
    }

    /// Convert to VALID
    pub fn to_valid(&self) -> Valid {
        Valid(self.0 * PROOF_PER_POAR * VALID_PER_PROOF)
    }

    /// Convert to ZERO
    pub fn to_zero(&self) -> Zero {
        Zero(self.0 * ZERO_PER_POAR)
    }

    /// Get raw amount
    pub fn amount(&self) -> u128 {
        self.0
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl Proof {
    /// Create new PROOF amount
    pub fn new(amount: u128) -> Self {
        Self(amount)
    }

    /// Convert to POAR (truncates)
    pub fn to_poar(&self) -> Poar {
        Poar(self.0 / PROOF_PER_POAR)
    }

    /// Convert to VALID
    pub fn to_valid(&self) -> Valid {
        Valid(self.0 * VALID_PER_PROOF)
    }

    /// Convert to ZERO
    pub fn to_zero(&self) -> Zero {
        Zero(self.0 * VALID_PER_PROOF * ZERO_PER_VALID)
    }

    /// Get raw amount
    pub fn amount(&self) -> u128 {
        self.0
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl Valid {
    /// Create new VALID amount
    pub fn new(amount: u128) -> Self {
        Self(amount)
    }

    /// Convert to POAR (truncates)
    pub fn to_poar(&self) -> Poar {
        Poar(self.0 / (PROOF_PER_POAR * VALID_PER_PROOF))
    }

    /// Convert to PROOF (truncates)
    pub fn to_proof(&self) -> Proof {
        Proof(self.0 / VALID_PER_PROOF)
    }

    /// Convert to ZERO
    pub fn to_zero(&self) -> Zero {
        Zero(self.0 * ZERO_PER_VALID)
    }

    /// Get raw amount
    pub fn amount(&self) -> u128 {
        self.0
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl Zero {
    /// Create new ZERO amount
    pub fn new(amount: u128) -> Self {
        Self(amount)
    }

    /// Convert to POAR (truncates)
    pub fn to_poar(&self) -> Poar {
        Poar(self.0 / ZERO_PER_POAR)
    }

    /// Convert to PROOF (truncates)
    pub fn to_proof(&self) -> Proof {
        Proof(self.0 / (VALID_PER_PROOF * ZERO_PER_VALID))
    }

    /// Convert to VALID (truncates)
    pub fn to_valid(&self) -> Valid {
        Valid(self.0 / ZERO_PER_VALID)
    }

    /// Get raw amount
    pub fn amount(&self) -> u128 {
        self.0
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

// Display implementations
impl fmt::Display for Poar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} POAR", self.0)
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} PROOF", self.0)
    }
}

impl fmt::Display for Valid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} VALID", self.0)
    }
}

impl fmt::Display for Zero {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ZERO", self.0)
    }
}

// Arithmetic operations for Poar
impl std::ops::Add for Poar {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Sub for Poar {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl std::ops::Mul<u128> for Poar {
    type Output = Self;
    fn mul(self, rhs: u128) -> Self {
        Self(self.0 * rhs)
    }
}

impl std::ops::Div<u128> for Poar {
    type Output = Self;
    fn div(self, rhs: u128) -> Self {
        Self(self.0 / rhs)
    }
}

// Arithmetic operations for Proof
impl std::ops::Add for Proof {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Sub for Proof {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl std::ops::Mul<u128> for Proof {
    type Output = Self;
    fn mul(self, rhs: u128) -> Self {
        Self(self.0 * rhs)
    }
}

impl std::ops::Div<u128> for Proof {
    type Output = Self;
    fn div(self, rhs: u128) -> Self {
        Self(self.0 / rhs)
    }
}

// Arithmetic operations for Valid
impl std::ops::Add for Valid {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Sub for Valid {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl std::ops::Mul<u128> for Valid {
    type Output = Self;
    fn mul(self, rhs: u128) -> Self {
        Self(self.0 * rhs)
    }
}

impl std::ops::Div<u128> for Valid {
    type Output = Self;
    fn div(self, rhs: u128) -> Self {
        Self(self.0 / rhs)
    }
}

// Arithmetic operations for Zero
impl std::ops::Add for Zero {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Sub for Zero {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl std::ops::Mul<u128> for Zero {
    type Output = Self;
    fn mul(self, rhs: u128) -> Self {
        Self(self.0 * rhs)
    }
}

impl std::ops::Div<u128> for Zero {
    type Output = Self;
    fn div(self, rhs: u128) -> Self {
        Self(self.0 / rhs)
    }
}

// Default implementations
impl Default for Poar {
    fn default() -> Self {
        Self(0)
    }
}

impl Default for Proof {
    fn default() -> Self {
        Self(0)
    }
}

impl Default for Valid {
    fn default() -> Self {
        Self(0)
    }
}

impl Default for Zero {
    fn default() -> Self {
        Self(0)
    }
}

/// Token utility functions
pub struct TokenUtils;

impl TokenUtils {
    /// Format token amount with proper unit display
    pub fn format_amount(amount: u128, unit: TokenUnit) -> String {
        match unit {
            TokenUnit::Poar => format!("{} POAR", amount),
            TokenUnit::Proof => format!("{} PROOF", amount),
            TokenUnit::Valid => format!("{} VALID", amount),
            TokenUnit::Zero => format!("{} ZERO", amount),
        }
    }

    /// Parse token amount from string
    pub fn parse_amount(input: &str) -> Result<TokenAmount, String> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.len() != 2 {
            return Err("Invalid format. Expected: <amount> <unit>".to_string());
        }

        let amount: u128 = parts[0].parse().map_err(|_| "Invalid amount")?;
        let unit = match parts[1].to_uppercase().as_str() {
            "POAR" => TokenUnit::Poar,
            "PROOF" => TokenUnit::Proof,
            "VALID" => TokenUnit::Valid,
            "ZERO" => TokenUnit::Zero,
            _ => return Err("Invalid unit. Use: POAR, PROOF, VALID, ZERO".to_string()),
        };

        Ok(TokenAmount { amount, unit })
    }

    /// Convert between token units
    pub fn convert(amount: u128, from_unit: TokenUnit, to_unit: TokenUnit) -> u128 {
        match (from_unit, to_unit) {
            (TokenUnit::Poar, TokenUnit::Proof) => amount * PROOF_PER_POAR,
            (TokenUnit::Poar, TokenUnit::Valid) => amount * PROOF_PER_POAR * VALID_PER_PROOF,
            (TokenUnit::Poar, TokenUnit::Zero) => amount * ZERO_PER_POAR,
            (TokenUnit::Proof, TokenUnit::Poar) => amount / PROOF_PER_POAR,
            (TokenUnit::Proof, TokenUnit::Valid) => amount * VALID_PER_PROOF,
            (TokenUnit::Proof, TokenUnit::Zero) => amount * VALID_PER_PROOF * ZERO_PER_VALID,
            (TokenUnit::Valid, TokenUnit::Poar) => amount / (PROOF_PER_POAR * VALID_PER_PROOF),
            (TokenUnit::Valid, TokenUnit::Proof) => amount / VALID_PER_PROOF,
            (TokenUnit::Valid, TokenUnit::Zero) => amount * ZERO_PER_VALID,
            (TokenUnit::Zero, TokenUnit::Poar) => amount / ZERO_PER_POAR,
            (TokenUnit::Zero, TokenUnit::Proof) => amount / (VALID_PER_PROOF * ZERO_PER_VALID),
            (TokenUnit::Zero, TokenUnit::Valid) => amount / ZERO_PER_VALID,
            // Same unit
            (TokenUnit::Poar, TokenUnit::Poar) => amount,
            (TokenUnit::Proof, TokenUnit::Proof) => amount,
            (TokenUnit::Valid, TokenUnit::Valid) => amount,
            (TokenUnit::Zero, TokenUnit::Zero) => amount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_conversion_constants() {
        // Test conversion constants
        assert_eq!(PROOF_PER_POAR, 1_000_000_000u128);
        assert_eq!(VALID_PER_PROOF, 1_000_000_000u128);
        assert_eq!(ZERO_PER_VALID, 1_000_000_000u128);
        assert_eq!(ZERO_PER_POAR, 1_000_000_000_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_poar_creation_and_conversion() {
        let poar = Poar::new(1u128);
        assert_eq!(poar.amount(), 1u128);
        assert_eq!(poar.to_string(), "1 POAR");

        // Test conversions
        let proof = poar.to_proof();
        assert_eq!(proof.amount(), 1_000_000_000u128);

        let valid = poar.to_valid();
        assert_eq!(valid.amount(), 1_000_000_000_000_000_000u128);

        let zero = poar.to_zero();
        assert_eq!(zero.amount(), 1_000_000_000_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_proof_creation_and_conversion() {
        let proof = Proof::new(1_000_000_000u128);
        assert_eq!(proof.amount(), 1_000_000_000u128);
        assert_eq!(proof.to_string(), "1000000000 PROOF");

        // Test conversions
        let poar = proof.to_poar();
        assert_eq!(poar.amount(), 1u128);

        let valid = proof.to_valid();
        assert_eq!(valid.amount(), 1_000_000_000_000_000_000u128); // updated expected value

        let zero = proof.to_zero();
        assert_eq!(zero.amount(), 1_000_000_000_000_000_000_000_000_000u128); // updated expected value
    }

    #[test]
    fn test_valid_creation_and_conversion() {
        let valid = Valid::new(1_000_000_000u128);
        assert_eq!(valid.amount(), 1_000_000_000u128);
        assert_eq!(valid.to_string(), "1000000000 VALID");

        // Test conversions
        let poar = valid.to_poar();
        assert_eq!(poar.amount(), 0u128); // Truncates to 0

        let proof = valid.to_proof();
        assert_eq!(proof.amount(), 1u128);

        let zero = valid.to_zero();
        assert_eq!(zero.amount(), 1_000_000_000_000_000_000u128); // updated expected value
    }

    #[test]
    fn test_zero_creation_and_conversion() {
        let zero = Zero::new(1_000_000_000u128);
        assert_eq!(zero.amount(), 1_000_000_000u128);
        assert_eq!(zero.to_string(), "1000000000 ZERO");

        // Test conversions
        let poar = zero.to_poar();
        assert_eq!(poar.amount(), 0u128); // Truncates to 0

        let proof = zero.to_proof();
        assert_eq!(proof.amount(), 0u128); // Truncates to 0

        let valid = zero.to_valid();
        assert_eq!(valid.amount(), 1u128);
    }

    #[test]
    fn test_arithmetic_operations() {
        let poar1 = Poar::new(10u128);
        let poar2 = Poar::new(5u128);

        // Addition
        let sum = poar1 + poar2;
        assert_eq!(sum.amount(), 15u128);

        // Subtraction
        let diff = poar1 - poar2;
        assert_eq!(diff.amount(), 5u128);

        // Multiplication
        let product = poar1 * 3u128;
        assert_eq!(product.amount(), 30u128);

        // Division
        let quotient = poar1 / 2u128;
        assert_eq!(quotient.amount(), 5u128);
    }

    #[test]
    fn test_proof_arithmetic() {
        let proof1 = Proof::new(1_000_000_000u128);
        let proof2 = Proof::new(500_000_000u128);

        let sum = proof1 + proof2;
        assert_eq!(sum.amount(), 1_500_000_000u128);

        let diff = proof1 - proof2;
        assert_eq!(diff.amount(), 500_000_000u128);
    }

    #[test]
    fn test_valid_arithmetic() {
        let valid1 = Valid::new(1_000_000_000u128);
        let valid2 = Valid::new(500_000_000u128);

        let sum = valid1 + valid2;
        assert_eq!(sum.amount(), 1_500_000_000u128);

        let diff = valid1 - valid2;
        assert_eq!(diff.amount(), 500_000_000u128);
    }

    #[test]
    fn test_zero_arithmetic() {
        let zero1 = Zero::new(1_000_000_000u128);
        let zero2 = Zero::new(500_000_000u128);

        let sum = zero1 + zero2;
        assert_eq!(sum.amount(), 1_500_000_000u128);

        let diff = zero1 - zero2;
        assert_eq!(diff.amount(), 500_000_000u128);
    }

    #[test]
    fn test_token_utils_format() {
        assert_eq!(TokenUtils::format_amount(100u128, TokenUnit::Poar), "100 POAR");
        assert_eq!(TokenUtils::format_amount(1000u128, TokenUnit::Proof), "1000 PROOF");
        assert_eq!(TokenUtils::format_amount(500u128, TokenUnit::Valid), "500 VALID");
        assert_eq!(TokenUtils::format_amount(750u128, TokenUnit::Zero), "750 ZERO");
    }

    #[test]
    fn test_token_utils_parse() {
        let parsed = TokenUtils::parse_amount("100 POAR").unwrap();
        assert_eq!(parsed.amount, 100u128);
        assert_eq!(parsed.unit, TokenUnit::Poar);

        let parsed = TokenUtils::parse_amount("1000 PROOF").unwrap();
        assert_eq!(parsed.amount, 1000u128);
        assert_eq!(parsed.unit, TokenUnit::Proof);

        let parsed = TokenUtils::parse_amount("500 VALID").unwrap();
        assert_eq!(parsed.amount, 500u128);
        assert_eq!(parsed.unit, TokenUnit::Valid);

        let parsed = TokenUtils::parse_amount("750 ZERO").unwrap();
        assert_eq!(parsed.amount, 750u128);
        assert_eq!(parsed.unit, TokenUnit::Zero);
    }

    #[test]
    fn test_token_utils_parse_error() {
        // Invalid format
        assert!(TokenUtils::parse_amount("100").is_err());
        assert!(TokenUtils::parse_amount("POAR 100").is_err());

        // Invalid unit
        assert!(TokenUtils::parse_amount("100 ETH").is_err());

        // Invalid amount
        assert!(TokenUtils::parse_amount("abc POAR").is_err());
    }

    #[test]
    fn test_token_utils_convert() {
        // POAR to other units
        assert_eq!(TokenUtils::convert(1u128, TokenUnit::Poar, TokenUnit::Proof), 1_000_000_000u128);
        assert_eq!(TokenUtils::convert(1u128, TokenUnit::Poar, TokenUnit::Valid), 1_000_000_000_000_000_000u128);
        assert_eq!(TokenUtils::convert(1u128, TokenUnit::Poar, TokenUnit::Zero), 1_000_000_000_000_000_000_000_000_000u128);

        // PROOF to other units
        assert_eq!(TokenUtils::convert(1_000_000_000u128, TokenUnit::Proof, TokenUnit::Poar), 1u128);
        assert_eq!(TokenUtils::convert(1u128, TokenUnit::Proof, TokenUnit::Valid), 1_000_000_000u128);
        assert_eq!(TokenUtils::convert(1u128, TokenUnit::Proof, TokenUnit::Zero), 1_000_000_000_000_000_000u128);

        // VALID to other units
        assert_eq!(TokenUtils::convert(1_000_000_000u128, TokenUnit::Valid, TokenUnit::Proof), 1u128);
        assert_eq!(TokenUtils::convert(1u128, TokenUnit::Valid, TokenUnit::Zero), 1_000_000_000u128);

        // ZERO to other units
        assert_eq!(TokenUtils::convert(1_000_000_000u128, TokenUnit::Zero, TokenUnit::Valid), 1u128);

        // Same unit conversions
        assert_eq!(TokenUtils::convert(100u128, TokenUnit::Poar, TokenUnit::Poar), 100u128);
        assert_eq!(TokenUtils::convert(1000u128, TokenUnit::Proof, TokenUnit::Proof), 1000u128);
    }

    #[test]
    fn test_default_values() {
        assert_eq!(Poar::default().amount(), 0u128);
        assert_eq!(Proof::default().amount(), 0u128);
        assert_eq!(Valid::default().amount(), 0u128);
        assert_eq!(Zero::default().amount(), 0u128);
    }

    #[test]
    fn test_is_zero() {
        assert!(Poar::new(0u128).is_zero());
        assert!(!Poar::new(1u128).is_zero());

        assert!(Proof::new(0u128).is_zero());
        assert!(!Proof::new(1u128).is_zero());

        assert!(Valid::new(0u128).is_zero());
        assert!(!Valid::new(1u128).is_zero());

        assert!(Zero::new(0u128).is_zero());
        assert!(!Zero::new(1u128).is_zero());
    }

    #[test]
    fn test_comparison_operations() {
        let poar1 = Poar::new(10u128);
        let poar2 = Poar::new(5u128);
        let poar3 = Poar::new(10u128);

        assert!(poar1 > poar2);
        assert!(poar2 < poar1);
        assert_eq!(poar1, poar3);
        assert_ne!(poar1, poar2);
    }

    #[test]
    fn test_large_amounts() {
        // Test with large amounts to ensure no overflow
        let large_poar = Poar::new(u64::MAX.into());
        let large_proof = Proof::new(u64::MAX.into());
        let large_valid = Valid::new(u64::MAX.into());
        let large_zero = Zero::new(u64::MAX.into());

        // These should not panic
        let _ = large_poar.to_proof();
        let _ = large_proof.to_valid();
        let _ = large_valid.to_zero();
        let _ = large_zero.to_valid();
    }

    #[test]
    fn test_serialization() {
        let poar = Poar::new(100u128);
        let proof = Proof::new(1_000_000_000u128);
        let valid = Valid::new(1_000_000_000u128);
        let zero = Zero::new(1_000_000_000u128);

        // Test that values can be created and compared
        assert_eq!(poar.amount(), 100u128);
        assert_eq!(proof.amount(), 1_000_000_000u128);
        assert_eq!(valid.amount(), 1_000_000_000u128);
        assert_eq!(zero.amount(), 1_000_000_000u128);

        // Test that they can be converted
        assert_eq!(poar.to_proof().amount(), 100_000_000_000u128);
        assert_eq!(proof.to_valid().amount(), 1_000_000_000_000_000_000u128); // updated expected value
        assert_eq!(valid.to_zero().amount(), 1_000_000_000_000_000_000u128); // updated expected value
        assert_eq!(zero.to_valid().amount(), 1u128); // updated expected value
    }
} 