# Arbitrary CPI (Cross-Program Invocation) Vulnerabilities

## Summary

This example demonstrates vulnerabilities when calling other Solana programs:

1. **Arbitrary Program CPI** - Calling unvalidated programs
2. **Fake Token Program** - Substituting malicious token program
3. **Signer Seeds to Arbitrary Program** - Giving PDA authority to attackers
4. **Missing Executable Check** - Calling non-executable accounts

## The Core Problem

```rust
// VULNERABLE: No validation of which program we're calling!
pub swap_program: UncheckedAccount<'info>,

// Later in instruction:
invoke(&instruction, &accounts)?;  // Could be malicious program!
```

## Attack Scenarios

### Fake Swap Program Attack
1. Protocol aggregates swaps via CPI to "swap program"
2. Attacker deploys malicious program
3. Attacker calls our protocol with their program
4. Malicious program takes tokens but doesn't give anything back
5. Our protocol thinks swap succeeded

### Fake Token Program Attack
1. Protocol transfers tokens via CPI to "token program"
2. Attacker passes fake token program
3. Fake program does nothing but returns success
4. Protocol state updates (thinks transfer happened)
5. Attacker withdraws again and again

### PDA Authority Theft
1. Protocol has treasury PDA with funds
2. Protocol does CPI with signer seeds to "reward program"
3. Attacker passes malicious program
4. Malicious program uses our PDA's signing authority
5. Drains treasury to attacker's account

## The Fixes

### Use Program<> Types
```rust
// SECURE: Anchor validates this is the Token Program
pub token_program: Program<'info, Token>,
```

### Validate Program ID
```rust
// SECURE: Explicit address check
#[account(
    executable,
    address = EXPECTED_PROGRAM_ID @ Error::InvalidProgram
)]
pub external_program: UncheckedAccount<'info>,
```

### Check Executable
```rust
// SECURE: Verify account is actually a program
#[account(executable)]
pub program: UncheckedAccount<'info>,
```

## CPI Security Comparison

| Aspect | Vulnerable | Secure |
|--------|------------|--------|
| Program Type | `UncheckedAccount` | `Program<'info, T>` |
| ID Validation | None | Automatic or `address` |
| Executable Check | None | Automatic or `executable` |
| Signer Seeds | Passed to any program | Only to validated programs |

## Best Practices

1. **Always use `Program<'info, T>`** for standard programs
2. **Use `address` constraint** for custom program validation
3. **Add `executable` constraint** when using UncheckedAccount for programs
4. **Never pass signer seeds** to unvalidated programs
5. **Use Anchor's CPI helpers** (`token::transfer`, etc.)
6. **Store program IDs as constants** for clarity

## Signer Seeds Warning

When you use `invoke_signed` or `CpiContext::new_with_signer`, you're giving the called program the ability to act as your PDA. This is **extremely dangerous** if you don't validate the program:

```rust
// DANGEROUS: Unknown program can now act as your treasury!
invoke_signed(
    &unknown_instruction,
    &[treasury.to_account_info()],
    &[&[b"treasury", &[bump]]], // This gives away your PDA's authority!
)?;
```

## Files

- `src/lib.rs` - Four CPI vulnerability patterns with secure alternatives
