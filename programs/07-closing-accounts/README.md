# Closing Accounts Vulnerabilities

## Summary

Account closing introduces several vulnerabilities if not handled properly:

1. **Revival Attack** - Closed account reused in same transaction
2. **Rent Theft** - Unauthorized users closing accounts
3. **Stale Data** - Reading from defunded accounts
4. **PDA Recreation** - Closed PDAs can be recreated with same seeds

## Vulnerability 1: Revival Attack

```rust
// VULNERABLE: Just transferring lamports doesn't prevent revival
let lamports = account.lamports();
**account.try_borrow_mut_lamports()? = 0;
**recipient.try_borrow_mut_lamports()? += lamports;
// Data is still there! Account can be revived in same TX
```

### Attack Flow
```
1. close_vulnerable(user_account) - get lamports back
2. fund_account(user_account)     - re-add lamports in same TX
3. claim_rewards(user_account)    - data still exists!
4. Repeat until reward pool drained
```

### The Fix

```rust
// SECURE: Anchor's close constraint zeros data
#[account(
    mut,
    close = recipient,  // Zeros data + transfers lamports
    has_one = owner,    // Verify authority
)]
pub user_account: Account<'info, UserAccount>,
```

## Vulnerability 2: Missing Authority Check

```rust
// VULNERABLE: Anyone can close any account!
pub fn close(ctx: Context<Close>) -> Result<()> {
    // No check that signer owns the account
    transfer_lamports(account, attacker);  // Theft!
}
```

### The Fix

```rust
#[account(
    mut,
    close = recipient,
    has_one = owner,  // Only owner can close
)]
pub user_account: Account<'info, UserAccount>,

pub owner: Signer<'info>,  // Must sign
```

## Vulnerability 3: PDA Recreation

```rust
// Problem: After closing, PDA can be recreated with same seeds!
// seeds = [b"profile", owner.as_ref()]

// Attack:
// 1. User claims airdrop
// 2. Admin closes user's profile (marks as claimed)
// 3. User re-initializes profile (same seeds work!)
// 4. User claims airdrop again
```

### The Fix: Tombstone Pattern

```rust
#[derive(Accounts)]
pub struct CloseProfileSecure<'info> {
    #[account(mut, close = recipient)]
    pub profile: Account<'info, UserProfile>,
    
    // Create permanent tombstone record
    #[account(
        init,
        seeds = [b"tombstone", owner.key().as_ref()],
        bump
    )]
    pub tombstone: Account<'info, ProfileTombstone>,
}

// Future init must check tombstone doesn't exist
```

## What Anchor's `close` Does

| Step | Action |
|------|--------|
| 1 | Transfer all lamports to recipient |
| 2 | Zero out all account data |
| 3 | Set owner to System Program |
| 4 | Account will be garbage collected |

**Result:** Revival attacks prevented because data is zeroed!

## Best Practices

1. **Always use `close` constraint** - never manually transfer lamports
2. **Verify authority** with `has_one = owner`
3. **Use tombstone pattern** for PDAs that shouldn't be recreated
4. **Zero data before lamport transfer** if doing manual close
5. **Validate accounts** aren't defunded when reading

## Same-Transaction Revival

Even after closing, an account exists until the transaction ends:

```
Transaction {
    ix1: close(account)      // Lamports -> attacker, data zeroed
    ix2: fund(account)       // Send lamports back to account
    ix3: use(account)        // Account "exists" but data is zeroed
}
```

With Anchor's `close`: ix3 fails because discriminator is gone!
Without zeroing: ix3 might succeed with stale data!

## Files

- `src/lib.rs` - Four closing account vulnerability patterns with fixes
