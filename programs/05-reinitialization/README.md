# Reinitialization Attack Vulnerability

## Summary

Reinitialization attacks allow attackers to reset account state after it has been properly initialized, enabling them to:

- Change ownership of accounts
- Reset balances and counters
- Take control of protocol configurations

## The Vulnerability

```rust
// VULNERABLE: Can be called multiple times!
pub fn initialize_vulnerable(ctx: Context<InitializeVulnerable>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.authority = ctx.accounts.authority.key();  // Attacker becomes authority
    vault.balance = 0;  // Existing balance lost!
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeVulnerable<'info> {
    #[account(mut)]  // No `init` - allows reinitialization
    pub vault: Account<'info, Vault>,
}
```

## The Fix

```rust
// SECURE: Anchor's `init` ensures one-time initialization
pub fn initialize_secure(ctx: Context<InitializeSecure>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.authority = ctx.accounts.authority.key();
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeSecure<'info> {
    #[account(
        init,  // Creates account - fails if already exists
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
}
```

## Attack Scenarios

### Vault Takeover
1. Alice initializes vault with 100 SOL, authority = Alice
2. Attacker calls `initialize_vulnerable` on Alice's vault
3. Vault state becomes: balance = 0, authority = Attacker
4. Alice's 100 SOL is trapped (or attacker can withdraw)

### Protocol Hijack
1. Protocol deployed with admin = deployer, fee = 1%
2. Attacker calls `initialize_config` with their key
3. Config becomes: admin = attacker, fee = 100%
4. Attacker now controls entire protocol

## Defense Approaches

| Approach | Security | Recommendation |
|----------|----------|----------------|
| Manual `is_initialized` flag | Weak | Not recommended |
| Anchor `init` constraint | Strong | Recommended |
| PDA + `init` | Strongest | Best practice |

## Why Anchor's `init` Works

1. **Creates Account**: The account is created atomically
2. **Unique Address**: PDA seeds ensure unique addresses
3. **Discriminator**: 8-byte type identifier prevents confusion
4. **Owner Set**: Program automatically becomes owner
5. **Cannot Repeat**: Address already exists on second call

## The Manual Flag Problem

```rust
pub struct Vault {
    pub is_initialized: bool,  // Can be manipulated!
}

// Attacker with raw account access could:
// 1. Create account with is_initialized = false
// 2. Pass to initialize function
// 3. Bypass the check
```

Manual flags don't prevent:
- Raw account data manipulation
- Race conditions during initialization
- Type confusion attacks

## Files

- `src/lib.rs` - Three vulnerability patterns with secure alternatives
