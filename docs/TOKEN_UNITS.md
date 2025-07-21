# ZK-PoV Token Units Documentation

## 🎯 Overview

The ZK-PoV blockchain implements a comprehensive token unit system designed to reflect the technological foundation of Zero-Knowledge Proof of Validity consensus while providing practical utility for different transaction types and use cases.

## 📊 Token Hierarchy

The ZK-PoV token system consists of four hierarchical units:

```
1 POAR = 1,000,000,000 PROOF
1 PROOF = 1,000,000,000 VALID
1 VALID = 1,000,000,000 ZERO
```

**Total Decimals**: 27 (3 × 9 decimals)

### Unit Descriptions

| Unit      | Purpose        | Use Cases                                      | Technology Connection  |
| --------- | -------------- | ---------------------------------------------- | ---------------------- |
| **POAR**  | Main unit      | Enterprise transactions, staking, governance   | Blockchain foundation  |
| **PROOF** | ZK operations  | Block rewards, validator operations, ZK proofs | Zero-Knowledge Proofs  |
| **VALID** | Validation     | Regular transactions, fees, validation         | Transaction Validation |
| **ZERO**  | Micro-payments | Gas fees, micro-transactions, privacy          | Zero-Knowledge Privacy |

## 🔧 Technical Implementation

### Core Types

```rust
/// Main POAR token unit (1 POAR)
pub struct Poar(u64);

/// PROOF unit (1 POAR = 1,000,000,000 PROOF)
pub struct Proof(u64);

/// VALID unit (1 PROOF = 1,000,000,000 VALID)
pub struct Valid(u64);

/// ZERO unit (1 VALID = 1,000,000,000 ZERO)
pub struct Zero(u64);
```

### Conversion Constants

```rust
pub const PROOF_PER_POAR: u64 = 1_000_000_000;
pub const VALID_PER_PROOF: u64 = 1_000_000_000;
pub const ZERO_PER_VALID: u64 = 1_000_000_000;
pub const ZERO_PER_POAR: u64 = PROOF_PER_POAR * VALID_PER_PROOF * ZERO_PER_VALID;
```

## 🚀 Usage Examples

### Creating Token Amounts

```rust
use poar_core::types::{Poar, Proof, Valid, Zero};

// Create different token amounts
let poar_amount = Poar::new(100);
let proof_amount = Proof::new(1_000_000_000);
let valid_amount = Valid::new(1_000_000_000);
let zero_amount = Zero::new(1_000_000_000);
```

### Converting Between Units

```rust
// POAR to other units
let poar = Poar::new(1);
let proof = poar.to_proof();        // 1,000,000,000 PROOF
let valid = poar.to_valid();        // 1,000,000,000,000,000,000 VALID
let zero = poar.to_zero();          // 1,000,000,000,000,000,000,000,000,000 ZERO

// PROOF to other units
let proof = Proof::new(1_000_000_000);
let poar = proof.to_poar();         // 1 POAR
let valid = proof.to_valid();       // 1,000,000,000 VALID
let zero = proof.to_zero();         // 1,000,000,000,000,000,000 ZERO

// VALID to other units
let valid = Valid::new(1_000_000_000);
let proof = valid.to_proof();       // 1 PROOF
let zero = valid.to_zero();         // 1,000,000,000 ZERO

// ZERO to other units
let zero = Zero::new(1_000_000_000);
let valid = zero.to_valid();        // 1 VALID
```

### Arithmetic Operations

```rust
// Addition
let poar1 = Poar::new(10);
let poar2 = Poar::new(5);
let sum = poar1 + poar2;            // 15 POAR

// Subtraction
let diff = poar1 - poar2;           // 5 POAR

// Multiplication
let product = poar1 * 3;            // 30 POAR

// Division
let quotient = poar1 / 2;           // 5 POAR
```

### TokenUtils Functions

```rust
use poar_core::types::{TokenUtils, TokenUnit, TokenAmount};

// Format amounts
let formatted = TokenUtils::format_amount(100, TokenUnit::Poar);
// Returns: "100 POAR"

// Parse amounts from strings
let parsed = TokenUtils::parse_amount("100 POAR").unwrap();
// Returns: TokenAmount { amount: 100, unit: TokenUnit::Poar }

// Convert between units
let converted = TokenUtils::convert(1, TokenUnit::Poar, TokenUnit::Proof);
// Returns: 1_000_000_000
```

## 🏗️ Integration Points

### Transaction System

All transaction amounts and fees are stored in ZERO units (smallest unit):

```rust
pub struct Transaction {
    pub amount: u64,  // in ZERO units
    pub fee: u64,     // in ZERO units
    // ... other fields
}
```

### Consensus Engine

Validator staking and block rewards use appropriate token units:

```rust
// Minimum validator stake: 32 POAR
pub min_validator_stake: u64, // 32 * ZERO_PER_POAR

// Block reward: 100 PROOF per block
pub reward_per_block: u64, // 100 PROOF units
```

### Wallet System

Wallet provides balance methods for all token units:

```rust
impl WalletService {
    pub async fn get_balance(&self) -> Poar { /* ... */ }
    pub async fn get_balance_proof(&self) -> Proof { /* ... */ }
    pub async fn get_balance_valid(&self) -> Valid { /* ... */ }
    pub async fn get_balance_zero(&self) -> Zero { /* ... */ }
}
```

### State Storage

Account balances are stored in ZERO units with conversion methods:

```rust
impl GlobalState {
    pub fn get_balance(&self, address: &Address) -> u64 { /* ZERO units */ }
    pub fn get_balance_poar(&self, address: &Address) -> Poar { /* ... */ }
    pub fn get_balance_proof(&self, address: &Address) -> Proof { /* ... */ }
    pub fn get_balance_valid(&self, address: &Address) -> Valid { /* ... */ }
}
```

## 🎯 Use Case Examples

### Enterprise Transactions

```rust
// Large business transaction: 1000 POAR
let enterprise_tx = Transaction::new(
    from, to,
    1000 * ZERO_PER_POAR,  // amount in ZERO units
    10 * ZERO_PER_POAR,     // fee in ZERO units
    // ... other parameters
);
```

### Validator Staking

```rust
// Minimum stake: 32 POAR
let min_stake = 32 * ZERO_PER_POAR;

// Validator registration
let staking_tx = Transaction::new(
    validator_address, staking_contract,
    min_stake,  // 32 POAR in ZERO units
    1 * ZERO_PER_POAR,  // registration fee
    // ... other parameters
);
```

### Block Rewards

```rust
// Block reward: 100 PROOF
let block_reward = 100 * VALID_PER_PROOF * ZERO_PER_VALID;

// Distribute to validator
validator_balance += block_reward;
```

### Micro-Payments

```rust
// Small transaction: 0.001 POAR
let micro_amount = 1_000_000;  // 0.001 POAR in ZERO units

let micro_tx = Transaction::new(
    from, to,
    micro_amount,
    1000,  // small fee in ZERO units
    // ... other parameters
);
```

## 🔍 Error Handling

### Invalid Conversions

```rust
// Truncation warnings
let small_valid = Valid::new(1);
let poar = small_valid.to_poar();  // Returns 0 (truncates)
let proof = small_valid.to_proof(); // Returns 0 (truncates)
```

### Parsing Errors

```rust
// Invalid format
let result = TokenUtils::parse_amount("100");
assert!(result.is_err());

// Invalid unit
let result = TokenUtils::parse_amount("100 ETH");
assert!(result.is_err());

// Invalid amount
let result = TokenUtils::parse_amount("abc POAR");
assert!(result.is_err());
```

## 🧪 Testing

### Running Tests

```bash
# Run all token unit tests
cargo test token

# Run specific test
cargo test test_poar_creation_and_conversion

# Run with output
cargo test token -- --nocapture
```

### Test Coverage

The token unit system includes comprehensive tests covering:

- ✅ Token creation and conversion
- ✅ Arithmetic operations (Add, Sub, Mul, Div)
- ✅ TokenUtils functionality
- ✅ Error handling and validation
- ✅ Large number safety
- ✅ Serialization compatibility

## 🔄 Migration Guide

### From Single Unit System

If migrating from a single unit system:

1. **Update Transaction Creation**:

   ```rust
   // Old: amount in arbitrary units
   let amount = 1000;

   // New: amount in ZERO units
   let amount = 1000 * ZERO_PER_POAR;  // Convert to ZERO
   ```

2. **Update Balance Checks**:

   ```rust
   // Old: direct comparison
   if balance >= amount { /* ... */ }

   // New: ensure same units
   if balance >= amount { /* both in ZERO units */ }
   ```

3. **Update Display Logic**:

   ```rust
   // Old: display raw numbers
   println!("Balance: {}", balance);

   // New: format with units
   let poar_balance = Zero::new(balance).to_poar();
   println!("Balance: {}", poar_balance);
   ```

## 📈 Performance Considerations

### Memory Usage

- Each token type uses `u64` (8 bytes)
- No additional memory overhead for conversions
- Efficient arithmetic operations

### Conversion Performance

- Conversions are compile-time optimized
- No runtime allocation for conversions
- Constant-time operations for all conversions

### Storage Efficiency

- All balances stored in ZERO units (smallest unit)
- No storage overhead for multiple units
- Efficient serialization/deserialization

## 🔮 Future Enhancements

### Planned Features

1. **Decimal Support**: Add decimal precision for micro-transactions
2. **Custom Units**: Allow custom token unit definitions
3. **Unit Validation**: Compile-time unit checking
4. **Formatting Options**: Custom display formats
5. **Internationalization**: Multi-language unit names

### Extension Points

The token system is designed for extensibility:

```rust
// Future: Custom token units
pub struct CustomToken(u64, TokenUnit);

// Future: Decimal support
pub struct DecimalToken(f64, TokenUnit);

// Future: Unit validation
pub struct ValidatedToken<T: TokenUnit>(u64, T);
```

## 📚 API Reference

### Core Types

| Type    | Description        | Methods                                          |
| ------- | ------------------ | ------------------------------------------------ |
| `Poar`  | Main token unit    | `new()`, `to_proof()`, `to_valid()`, `to_zero()` |
| `Proof` | ZK proof unit      | `new()`, `to_poar()`, `to_valid()`, `to_zero()`  |
| `Valid` | Validation unit    | `new()`, `to_poar()`, `to_proof()`, `to_zero()`  |
| `Zero`  | Micro-payment unit | `new()`, `to_poar()`, `to_proof()`, `to_valid()` |

### TokenUtils Functions

| Function        | Description              | Parameters                                    | Returns                       |
| --------------- | ------------------------ | --------------------------------------------- | ----------------------------- |
| `format_amount` | Format amount with unit  | `amount: u64, unit: TokenUnit`                | `String`                      |
| `parse_amount`  | Parse amount from string | `input: &str`                                 | `Result<TokenAmount, String>` |
| `convert`       | Convert between units    | `amount: u64, from: TokenUnit, to: TokenUnit` | `u64`                         |

### Constants

| Constant          | Value         | Description           |
| ----------------- | ------------- | --------------------- |
| `PROOF_PER_POAR`  | 1,000,000,000 | PROOF units per POAR  |
| `VALID_PER_PROOF` | 1,000,000,000 | VALID units per PROOF |
| `ZERO_PER_VALID`  | 1,000,000,000 | ZERO units per VALID  |
| `ZERO_PER_POAR`   | 10²⁷          | ZERO units per POAR   |

## 🎯 Conclusion

The ZK-PoV token unit system provides a comprehensive, type-safe, and technology-driven approach to blockchain token management. By reflecting the underlying ZK-PoV technology in the token naming and providing practical utility for different transaction types, the system enhances both developer experience and user understanding of the blockchain's capabilities.

The system is designed for extensibility, performance, and ease of use while maintaining strict type safety and comprehensive testing coverage.
