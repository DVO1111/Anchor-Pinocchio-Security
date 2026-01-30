# Solana Security Patterns

> A comprehensive educational repository demonstrating common Solana program vulnerabilities and their secure alternatives.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Anchor](https://img.shields.io/badge/Anchor-0.30.1-blue)](https://www.anchor-lang.com/)
[![Solana](https://img.shields.io/badge/Solana-Security-purple)](https://solana.com/)

## Overview

Security remains one of the biggest challenges in Solana program development. Many exploits don't come from complex attacks, but from simple mistakes: missing account validation, incorrect authority checks, unsafe arithmetic, or misunderstood CPI behavior.

This repository provides **clear, educational security examples** contrasting vulnerable code with secure alternatives. Each vulnerability includes:

- **Vulnerable implementation** with detailed explanation
- **Secure implementation** with fix explanation
- **Attack scenarios** showing real exploitation
- **Comparison tables** for quick reference

## Who Is This For?

- Developers learning Solana/Anchor
- Security auditors looking for reference patterns
- Teams building security checklists
- Anyone wanting to understand Solana attack vectors

## Repository Structure

```
solana-security-patterns/
├── programs/
│   ├── 01-missing-signer-check/     # Authority verification vulnerabilities
│   ├── 02-account-validation/       # Owner, PDA, and relationship checks
│   ├── 03-integer-overflow/         # Arithmetic vulnerabilities
│   ├── 04-arbitrary-cpi/            # Cross-program invocation risks
│   ├── 05-reinitialization/         # Account reinitialization attacks
│   ├── 06-type-cosplay/             # Type confusion vulnerabilities
│   └── 07-closing-accounts/         # Account closing vulnerabilities
├── docs/
│   └── SECURITY_DEEP_DIVE.md        # Comprehensive security guide
├── Anchor.toml
├── Cargo.toml
└── README.md
```

## Vulnerability Coverage

| # | Vulnerability | Severity | Common? | Real Exploits |
|---|--------------|----------|---------|---------------|
| 1 | Missing Signer Check | Critical | Very High | Wormhole |
| 2 | Account Validation | Critical | High | Multiple DeFi |
| 3 | Integer Overflow | Critical | Medium | Token mints |
| 4 | Arbitrary CPI | Critical | Medium | Bridge attacks |
| 5 | Reinitialization | High | Medium | Protocol hijacks |
| 6 | Type Cosplay | High | Medium | Privilege escalation |
| 7 | Closing Accounts | Medium | High | Revival attacks |

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (1.70+)
- [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) (1.18+)
- [Anchor](https://www.anchor-lang.com/docs/installation) (0.30+)

### Build

```bash
# Clone the repository
git clone https://github.com/your-org/solana-security-patterns.git
cd solana-security-patterns

# Build all programs
anchor build
```

### Study a Pattern

Each program is self-contained with detailed comments:

```bash
# Navigate to a vulnerability example
cd programs/01-missing-signer-check

# Read the code (heavily commented!)
cat src/lib.rs

# Read the README for the vulnerability summary
cat README.md
```

## Vulnerability Summaries

### 1. Missing Signer Check

**The Problem:** Not verifying that an account actually signed the transaction.

```rust
// VULNERABLE
pub authority: UncheckedAccount<'info>,  // Anyone can pass any pubkey!

// SECURE  
pub authority: Signer<'info>,  // Must have signed the transaction
```

[Full Documentation](programs/01-missing-signer-check/README.md)

---

### 2. Account Validation

**The Problem:** Accepting accounts without verifying owner, PDA seeds, or relationships.

```rust
// VULNERABLE
pub pool: UncheckedAccount<'info>,  // Could be any account!

// SECURE
#[account(
    seeds = [b"pool", authority.key().as_ref()],
    bump = pool.bump,
)]
pub pool: Account<'info, Pool>,  // Validated PDA
```

[Full Documentation](programs/02-account-validation/README.md)

---

### 3. Integer Overflow

**The Problem:** Arithmetic operations that wrap around in release builds.

```rust
// VULNERABLE (wraps to 0 on overflow!)
vault.balance = vault.balance + amount;

// SECURE (returns error on overflow)
vault.balance = vault.balance.checked_add(amount).ok_or(MathError::Overflow)?;
```

[Full Documentation](programs/03-integer-overflow/README.md)

---

### 4. Arbitrary CPI

**The Problem:** Calling unvalidated programs, potentially giving them your PDA's authority.

```rust
// VULNERABLE
pub swap_program: UncheckedAccount<'info>,  // Could be malicious!

// SECURE
pub token_program: Program<'info, Token>,  // Validated program ID
```

[Full Documentation](programs/04-arbitrary-cpi/README.md)

---

### 5. Reinitialization

**The Problem:** Allowing accounts to be initialized multiple times.

```rust
// VULNERABLE
#[account(mut)]  // Can be called again!
pub vault: Account<'info, Vault>,

// SECURE
#[account(init, ...)]  // Creates new account - fails if exists
pub vault: Account<'info, Vault>,
```

[Full Documentation](programs/05-reinitialization/README.md)

---

### 6. Type Cosplay

**The Problem:** Passing one account type where another is expected.

```rust
// VULNERABLE
let is_admin = data[32] == 1;  // Just reading bytes!

// SECURE
pub admin_config: Account<'info, AdminConfig>,  // Type-validated
```

[Full Documentation](programs/06-type-cosplay/README.md)

---

### 7. Closing Accounts

**The Problem:** Improperly closing accounts, enabling revival attacks.

```rust
// VULNERABLE (data not zeroed!)
**account.lamports.borrow_mut() = 0;

// SECURE (Anchor zeros data)
#[account(mut, close = recipient)]
pub account: Account<'info, MyAccount>,
```

[Full Documentation](programs/07-closing-accounts/README.md)

## Security Checklist

Use this checklist when reviewing Solana programs:

### Account Validation
- [ ] All authority accounts use `Signer` type
- [ ] PDAs validated with `seeds` and `bump`
- [ ] Token accounts validated with `token::authority` and `token::mint`
- [ ] Account relationships validated with `has_one`
- [ ] Program accounts use `Program<'info, T>`

### Arithmetic Safety
- [ ] All arithmetic uses `checked_*` methods
- [ ] Type casts use `try_into()`
- [ ] Division handles zero and precision loss
- [ ] `overflow-checks = true` in release profile

### CPI Security
- [ ] External programs validated before CPI
- [ ] Never pass signer seeds to unvalidated programs
- [ ] `executable` constraint on program accounts

### State Management
- [ ] Account initialization uses `init` constraint
- [ ] Account closing uses `close` constraint
- [ ] Discriminators validated (use `Account<>` type)
- [ ] Consider tombstone pattern for PDA recreation

## Deep Dive Guide

For a comprehensive written guide covering all security patterns, attack scenarios, and best practices, see:

[Security Deep Dive Guide](docs/SECURITY_DEEP_DIVE.md)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your vulnerability example following the existing pattern
4. Include comprehensive comments and README
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Anchor Framework](https://www.anchor-lang.com/) - The foundation for secure Solana development
- [Solana Security Best Practices](https://github.com/coral-xyz/sealevel-attacks) - Inspiration and patterns
- [Neodyme Security Workshops](https://workshop.neodyme.io/) - Educational resources

## Disclaimer

This repository contains intentionally vulnerable code for educational purposes. **DO NOT** use the vulnerable patterns in production. The secure patterns demonstrate best practices but should be reviewed and tested thoroughly before use.

---

<p align="center">
  Built for the Solana developer community
</p>
#   A n c h o r - P i n o c c h i o - S e c u r i t y  
 