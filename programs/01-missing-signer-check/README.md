# Missing Signer Check Vulnerability

## Summary

This example demonstrates a critical vulnerability where an instruction fails to verify that an account actually signed the transaction.

## The Vulnerability

```rust
// VULNERABLE: authority is UncheckedAccount - no signature verification!
pub authority: UncheckedAccount<'info>,
```

Without the `Signer` constraint, anyone can pass any pubkey as the authority. The program has no way to know if that account holder actually authorized the action.

## The Fix

```rust
// SECURE: Signer constraint enforces signature verification
pub authority: Signer<'info>,
```

The `Signer` type tells Anchor to automatically verify that this account is in the transaction's list of signers.

## Attack Scenario

1. Alice creates a vault with 100 SOL, authority = Alice's pubkey
2. Bob (attacker) sees the vault on-chain
3. Bob calls `withdraw_vulnerable` with:
   - authority = Alice's pubkey (Bob knows this from chain data)
   - vault = Alice's vault
   - recipient = Bob's account
4. The program checks `vault.authority == authority.key()` (matches!)
5. But it never checked if Alice actually signed!
6. Bob drains Alice's vault

## Impact

- **Severity**: Critical
- **Likelihood**: High (common mistake)
- **Real-world examples**: Wormhole bridge exploit, multiple DeFi protocol hacks

## Best Practices

1. **Always use `Signer`** for any account that authorizes an action
2. **Never use `UncheckedAccount`** for authority/admin accounts
3. **Combine constraints**: Use both `Signer` AND pubkey validation
4. **Test for missing signers** in your test suite

## Files

- `src/lib.rs` - Complete implementation with vulnerable and secure versions
