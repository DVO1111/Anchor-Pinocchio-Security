# Integer Overflow/Underflow Vulnerabilities

## Summary

This example demonstrates arithmetic vulnerabilities in Solana programs:

1. **Addition Overflow** - Balance wraps to small number
2. **Subtraction Underflow** - Infinite money exploit
3. **Multiplication Overflow** - Large numbers wrap
4. **Type Casting Truncation** - High bits silently dropped
5. **Division Precision Loss** - Zero fee exploit

## Rust's Dangerous Default

```rust
// In release builds, this silently wraps around!
let result = u64::MAX + 1;  // = 0, not an error!
let result = 0u64 - 1;      // = 18446744073709551615, not an error!
```

Debug builds panic on overflow. **Release builds silently wrap.**

## Vulnerabilities

### 1. Addition Overflow

```rust
// VULNERABLE: Wraps to small number
vault.balance = vault.balance + amount;

// SECURE: Returns error on overflow
vault.balance = vault.balance.checked_add(amount).ok_or(err)?;
```

### 2. Subtraction Underflow

```rust
// VULNERABLE: 100 - 101 = u64::MAX (infinite money!)
balance = balance - amount;

// SECURE: Returns error if insufficient
balance = balance.checked_sub(amount).ok_or(err)?;
```

### 3. Multiplication Overflow

```rust
// VULNERABLE: 5B * 4B overflows
let total = price * quantity;

// SECURE: Catches overflow
let total = price.checked_mul(quantity).ok_or(err)?;
```

### 4. Casting Truncation

```rust
// VULNERABLE: Drops high 32 bits
let small: u32 = big_value as u32;

// SECURE: Returns error if doesn't fit
let small: u32 = big_value.try_into().map_err(|_| err)?;
```

### 5. Division Precision

```rust
// VULNERABLE: Small amounts = 0 fee
let fee = amount * fee_bps / 10000;

// SECURE: Ceiling division
let fee = (amount * fee_bps + 9999) / 10000;
```

## Attack Scenarios

### Underflow Attack (Infinite Money)
1. User has balance of 100 tokens
2. User calls `withdraw_vulnerable(101)`
3. `100 - 101` underflows to `18446744073709551615`
4. User now has near-infinite balance

### Overflow Attack (Lost Deposits)
1. Vault has `u64::MAX - 100` deposited
2. Attacker deposits 200
3. Balance wraps to 99
4. Previous depositors' funds "disappear"

### Zero Fee Attack
1. Protocol charges 1% fee (100 bps)
2. Attacker splits large transfer into 99-token chunks
3. `99 * 100 / 10000 = 0` (integer division)
4. Attacker pays zero fees

## Safe Math Methods

| Unsafe | Safe | Behavior on Error |
|--------|------|-------------------|
| `a + b` | `a.checked_add(b)` | Returns `None` |
| `a - b` | `a.checked_sub(b)` | Returns `None` |
| `a * b` | `a.checked_mul(b)` | Returns `None` |
| `a / b` | `a.checked_div(b)` | Returns `None` |
| `a as T` | `a.try_into()` | Returns `Err` |
| `a.pow(b)` | `a.checked_pow(b)` | Returns `None` |

## Best Practices

1. **Always use checked arithmetic** for user-provided values
2. **Enable overflow checks in release** via `Cargo.toml`:
   ```toml
   [profile.release]
   overflow-checks = true
   ```
3. **Use saturating arithmetic** when capping is acceptable:
   ```rust
   balance.saturating_add(amount)  // Caps at u64::MAX
   ```
4. **Consider using u128** for intermediate calculations
5. **Implement minimum fees** to prevent division attacks
6. **Create safe math helpers** for consistent error handling

## Files

- `src/lib.rs` - All five vulnerability patterns with fixes
- Includes `safe_math` module with reusable helper functions
