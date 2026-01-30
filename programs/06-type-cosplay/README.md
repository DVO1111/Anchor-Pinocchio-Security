# Type Cosplay Attack Vulnerability

## Summary

Type cosplay occurs when an attacker passes an account of one type where another type is expected. Without discriminator validation, the program misinterprets account data.

## The Vulnerability

```rust
// VULNERABLE: Reads raw bytes without type validation
let data = ctx.accounts.admin_config.try_borrow_data()?;
let admin_pubkey = Pubkey::try_from(&data[0..32]).unwrap();
let is_admin = data[32] == 1;  // Just a byte - could be anything!
```

## The Fix

```rust
// SECURE: Account<> validates discriminator
#[account(seeds = [b"admin_config"], bump = admin_config.bump)]
pub admin_config: Account<'info, AdminConfig>,

// Now guaranteed to be AdminConfig type
let admin = config.admin;  // Type-safe access
```

## Attack Scenarios

### Privilege Escalation Attack

**Account Layouts:**
```
AdminConfig:          UserAccount:
┌────────────────┐    ┌────────────────┐
│ admin (32)     │    │ owner (32)     │
├────────────────┤    ├────────────────┤
│ is_admin (1)   │    │ balance (8)    │
└────────────────┘    │ ...            │
                      └────────────────┘
```

**Attack:**
1. Attacker creates UserAccount with balance = 1
2. At byte 32, the value is 0x01 (first byte of balance)
3. When read as AdminConfig, `is_admin = data[32] == 1` is TRUE
4. Attacker gains admin privileges!

### Asset Theft via Same Layout

```rust
// UserVault and RewardVault have identical layouts!
pub struct UserVault {
    pub owner: Pubkey,    // 32 bytes
    pub balance: u64,     // 8 bytes
}

pub struct RewardVault {
    pub authority: Pubkey,  // 32 bytes
    pub balance: u64,       // 8 bytes
}
```

**Attack:**
1. Attacker creates UserVault with balance = 1000
2. Passes it to claim_rewards expecting RewardVault
3. Program reads 1000 as reward balance
4. Attacker claims 1000 tokens from reward pool

## How Discriminators Prevent This

Anchor generates unique 8-byte discriminators:

```
AdminConfig  → sha256("account:AdminConfig")[0..8]  → [68, 212, ...]
UserAccount  → sha256("account:UserAccount")[0..8]  → [124, 45, ...]
RewardVault  → sha256("account:RewardVault")[0..8]  → [87, 156, ...]
```

When deserializing:
1. Read first 8 bytes
2. Compare to expected discriminator
3. Fail if mismatch

**Result:** UserAccount can NEVER be mistaken for AdminConfig!

## Best Practices

1. **Always use `Account<'info, T>`** for typed accounts
2. **Never use raw byte reading** for account data
3. **Use different PDA seeds** for different account types
4. **Don't rely on manual type flags** - they can be spoofed
5. **Let Anchor handle discriminators** - don't roll your own

## Why Manual Type Flags Fail

```rust
pub struct GenericAccount {
    pub account_type: u8,  // 1 = User, 2 = Admin
    pub data: [u8; 100],
}
```

**Problem:** Anyone can create an account with `account_type = 2`!

Discriminators work because:
- They're set by Anchor during `init`
- They're cryptographic hashes
- Users can't choose arbitrary values

## Files

- `src/lib.rs` - Three type cosplay vulnerability patterns with fixes
