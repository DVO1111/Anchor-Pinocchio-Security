# Account Validation & Owner Check Vulnerabilities

## Summary

This example demonstrates three related vulnerabilities involving insufficient account validation:

1. **Missing Owner Check** - Accepting accounts owned by wrong programs
2. **Missing PDA Validation** - Not verifying PDA derivation
3. **Account Substitution** - Not validating account relationships

## Vulnerability 1: Missing Owner Check

```rust
// VULNERABLE: Accepts any account regardless of owner
pub pool_info: UncheckedAccount<'info>,
```

Without owner validation, attackers can create fake accounts with malicious data.

### The Fix

```rust
// SECURE: Account<> validates owner and deserializes safely
pub pool: Account<'info, Pool>,
```

## Vulnerability 2: Missing PDA Validation

```rust
// VULNERABLE: No seed validation - any account accepted
pub config: UncheckedAccount<'info>,
```

PDAs must be validated with their derivation seeds.

### The Fix

```rust
// SECURE: Seeds constraint validates PDA derivation
#[account(
    seeds = [b"config"],
    bump = config.bump,
)]
pub config: Account<'info, Config>,
```

## Vulnerability 3: Account Substitution

```rust
// VULNERABLE: No check that token account belongs to user
pub user_token_account: UncheckedAccount<'info>,
```

### The Fix

```rust
// SECURE: Validates token account ownership
#[account(
    mut,
    token::authority = user,  // Ensures token account is owned by signer
    token::mint = expected_mint,
)]
pub user_token_account: Account<'info, TokenAccount>,
```

## Attack Scenarios

### Fake Pool Attack
1. Attacker creates account with fabricated Pool data
2. Sets `reward_rate` to extremely high value
3. Calls `claim_rewards_vulnerable` 
4. Claims massive rewards from fake state

### PDA Substitution Attack
1. Protocol config has `fee_bps = 100` (1% fee)
2. Attacker creates fake config with `fee_bps = 0`
3. Swaps tokens paying 0% fee

### Token Account Theft
1. Attacker calls deposit with their signer
2. Passes victim's token account
3. Victim's tokens deposited to attacker's credit

## Anchor's Account<> Validation

When you use `Account<'info, T>`, Anchor automatically:

| Check | Description |
|-------|-------------|
| Owner | Verifies account is owned by your program |
| Discriminator | Validates 8-byte type identifier |
| Deserialization | Safely parses account data |
| Type Safety | Compile-time type guarantees |

## Best Practices

1. **Never use UncheckedAccount** for program-owned state
2. **Always validate PDA seeds** with `seeds` and `bump`
3. **Validate token account ownership** with `token::authority`
4. **Use `has_one`** to validate account relationships
5. **Validate all accounts** - assume nothing about inputs

## Files

- `src/lib.rs` - Complete implementation with all three vulnerability patterns
