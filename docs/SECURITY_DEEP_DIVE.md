# Solana Security Deep Dive

> A comprehensive guide to understanding and preventing common Solana program vulnerabilities.

## Table of Contents

1. [Understanding Solana's Security Model](#understanding-solanas-security-model)
2. [The Anchor Safety Net](#the-anchor-safety-net)
3. [Vulnerability Deep Dives](#vulnerability-deep-dives)
4. [Real-World Exploit Analysis](#real-world-exploit-analysis)
5. [Security Testing Strategies](#security-testing-strategies)
6. [Audit Checklist](#audit-checklist)

---

## Understanding Solana's Security Model

### The Account Model

Unlike Ethereum's contract-centric model, Solana uses an **account model** where:

- **Programs are stateless** - They don't store data themselves
- **Data lives in accounts** - Programs read/write to external accounts
- **Accounts are passed as inputs** - Your program receives accounts from the caller

This creates a fundamental security challenge: **You must validate every account passed to your program.**

```
Traditional (Ethereum):
┌─────────────────┐
│    Contract     │
│  ┌───────────┐  │
│  │   State   │  │  ← State lives inside contract
│  └───────────┘  │
└─────────────────┘

Solana:
┌─────────────┐        ┌─────────────┐
│   Program   │───────▶│   Account   │  ← Program reads/writes
│  (no state) │        │   (state)   │     external accounts
└─────────────┘        └─────────────┘
                              ▲
                              │
                       Caller provides
                       account reference
```

### Why Validation Matters

When a user calls your program, they provide:
1. The instruction data
2. A list of account references

**Your program must verify:**
- Each account is what it claims to be
- The caller is authorized to perform the action
- All data is within expected bounds

Without validation, attackers can:
- Pass fake accounts with malicious data
- Impersonate authorities
- Manipulate program state

---

## The Anchor Safety Net

Anchor provides automatic validation through its type system. Understanding what Anchor validates (and doesn't) is crucial.

### What `Account<'info, T>` Validates

```rust
pub vault: Account<'info, Vault>,
```

When you use `Account<'info, T>`, Anchor automatically checks:

| Check | What It Does |
|-------|-------------|
| **Owner** | Account is owned by your program |
| **Discriminator** | First 8 bytes match expected type |
| **Deserialization** | Data successfully parses as type T |

### What `Signer` Validates

```rust
pub authority: Signer<'info>,
```

Anchor verifies:
- Account is in transaction's signer list
- Transaction includes valid signature for this pubkey

### What `Program<'info, T>` Validates

```rust
pub token_program: Program<'info, Token>,
```

Anchor verifies:
- Account is executable
- Account key matches expected program ID

### What Anchor Does NOT Automatically Validate

- **Relationships between accounts** (use `has_one`, `constraint`)
- **PDA derivation** (use `seeds`, `bump`)
- **Business logic** (custom `constraint` expressions)
- **Arithmetic safety** (use `checked_*` methods)

---

## Vulnerability Deep Dives

### 1. Missing Signer Check

#### The Vulnerability

The signer check vulnerability occurs when a program accepts an "authority" account without verifying it actually signed the transaction.

```rust
// VULNERABLE: authority is UncheckedAccount
pub authority: UncheckedAccount<'info>,

// In instruction:
require!(vault.authority == authority.key(), Error);  // USELESS!
```

**Why the pubkey check is useless:**
- Pubkeys are public - anyone can read them from the chain
- The check verifies "is this the right pubkey?" Yes
- But it doesn't verify "did this pubkey's owner authorize this?" No

#### The Attack

```
1. Attacker reads Alice's vault from chain
2. Learns vault.authority = Alice's pubkey (public info!)
3. Attacker calls withdraw(authority: Alice's pubkey, vault: Alice's vault)
4. Program checks: vault.authority == authority.key()? Yes!
5. Program transfers funds to attacker
6. Alice never signed anything - her funds are gone
```

#### The Fix

```rust
// SECURE: authority must be Signer
pub authority: Signer<'info>,
```

The `Signer` constraint means:
- Anchor checks the account is in the transaction's signer list
- Transaction must include valid Ed25519 signature
- Cannot be faked - cryptographically enforced

---

### 2. Account Validation Failures

#### Missing Owner Check

**The Vulnerability:**
```rust
pub pool: UncheckedAccount<'info>,

// Reading raw data without validation
let data = pool.try_borrow_data()?;
let balance = u64::from_le_bytes(data[0..8].try_into()?);
```

Anyone can create an account with arbitrary data and pass it as `pool`.

**The Attack:**
1. Attacker creates account with System Program as owner
2. Writes fake data: balance = 1,000,000,000
3. Passes to program claiming it's a "pool" account
4. Program reads attacker's fabricated data

**The Fix:**
```rust
// Account<> validates owner and discriminator
pub pool: Account<'info, Pool>,
```

#### Missing PDA Validation

**The Vulnerability:**
```rust
// No seed validation - any account accepted
pub config: Account<'info, Config>,
```

Even with owner check, attacker might have another Config account with different data.

**The Attack:**
1. Protocol has official config at PDA with seeds ["config"]
2. Attacker creates their own Config account (different address)
3. Sets fee_bps = 0 in their config
4. Passes their config instead of protocol's config
5. Swaps tokens with 0% fee

**The Fix:**
```rust
#[account(
    seeds = [b"config"],
    bump = config.bump,
)]
pub config: Account<'info, Config>,
```

---

### 3. Integer Overflow/Underflow

#### The Danger

Rust's default arithmetic in **release builds** wraps around silently:

```rust
let a: u64 = u64::MAX;  // 18446744073709551615
let b: u64 = a + 1;     // 0 (wrapped around!)

let c: u64 = 0;
let d: u64 = c - 1;     // 18446744073709551615 (wrapped around!)
```

#### Attack: Underflow for Infinite Money

```rust
// VULNERABLE
user.balance = user.balance - withdrawal_amount;
```

**Attack:**
1. User has balance = 100
2. User withdraws 101
3. 100 - 101 = underflow = 18446744073709551615
4. User now has "infinite" balance

#### Attack: Overflow to Lose Deposits

```rust
// VULNERABLE
vault.total = vault.total + deposit_amount;
```

**Attack:**
1. Vault has total = u64::MAX - 100
2. Attacker deposits 200
3. (u64::MAX - 100) + 200 = 99 (overflow!)
4. Previous depositors' funds "disappeared"

#### The Fix

```rust
// Always use checked arithmetic
vault.balance = vault.balance
    .checked_add(amount)
    .ok_or(Error::Overflow)?;

user.balance = user.balance
    .checked_sub(amount)
    .ok_or(Error::InsufficientFunds)?;
```

#### Cargo.toml Protection

```toml
[profile.release]
overflow-checks = true  # Panics on overflow even in release
```

---

### 4. Arbitrary CPI Attacks

#### The Vulnerability

Cross-Program Invocation (CPI) lets your program call other programs. If you don't validate which program you're calling, attackers can substitute malicious programs.

```rust
// VULNERABLE: No program validation
pub swap_program: UncheckedAccount<'info>,

// Later:
invoke(&swap_instruction, &accounts)?;  // Calling attacker's program!
```

#### The Most Dangerous: Signer Seeds to Arbitrary Program

When you use `invoke_signed`, you're letting the called program act as your PDA:

```rust
// EXTREMELY DANGEROUS
invoke_signed(
    &malicious_instruction,
    &[treasury.to_account_info()],
    &[&[b"treasury", &[bump]]],  // Giving attacker your PDA's authority!
)?;
```

**Attack:**
1. Protocol has treasury PDA with 1000 SOL
2. Attacker passes malicious "reward_program"
3. Protocol CPIs to malicious program with treasury signer seeds
4. Malicious program transfers all treasury funds to attacker
5. Treasury drained in one transaction

#### The Fix

```rust
// Use Program<> types for standard programs
pub token_program: Program<'info, Token>,

// Validate custom programs
#[account(
    executable,
    address = EXPECTED_PROGRAM_ID @ Error::InvalidProgram
)]
pub external_program: UncheckedAccount<'info>,
```

---

### 5. Reinitialization Attacks

#### The Vulnerability

If an `initialize` instruction doesn't check whether the account is already initialized, attackers can reinitialize it.

```rust
// VULNERABLE: Can be called multiple times
#[account(mut)]
pub vault: Account<'info, Vault>,

pub fn initialize(ctx: Context<Init>) {
    let vault = &mut ctx.accounts.vault;
    vault.authority = ctx.accounts.signer.key();  // Attacker becomes owner!
    vault.balance = 0;  // Existing balance erased!
}
```

#### The Attack

```
1. Alice creates vault: authority = Alice, balance = 1000
2. Attacker calls initialize on Alice's vault
3. Vault becomes: authority = Attacker, balance = 0
4. Alice's 1000 tokens are trapped (or attacker withdraws)
```

#### The Fix

```rust
// SECURE: init creates new account
#[account(
    init,
    payer = authority,
    space = 8 + Vault::INIT_SPACE,
    seeds = [b"vault", authority.key().as_ref()],
    bump
)]
pub vault: Account<'info, Vault>,
```

**Why `init` is secure:**
- Creates new account at PDA address
- If account already exists, transaction fails
- Atomically sets discriminator and owner

---

### 6. Type Cosplay Attacks

#### The Vulnerability

Without discriminator validation, different account types with similar layouts can be confused.

```rust
// These have the same layout!
pub struct UserAccount {
    pub owner: Pubkey,    // 32 bytes
    pub balance: u64,     // 8 bytes
}

pub struct RewardVault {
    pub authority: Pubkey,  // 32 bytes
    pub rewards: u64,       // 8 bytes
}
```

If you read raw bytes:
```rust
// VULNERABLE
let data = account.try_borrow_data()?;;
let rewards = u64::from_le_bytes(data[32..40].try_into()?);
```

UserAccount can be passed as RewardVault!

#### The Attack

```
1. Attacker creates UserAccount with balance = 1_000_000
2. Passes it to claim_rewards expecting RewardVault
3. Program reads balance field as rewards field
4. Attacker claims 1_000_000 from reward pool
```

#### The Fix

```rust
// SECURE: Anchor validates discriminator
pub reward_vault: Account<'info, RewardVault>,
```

Anchor's discriminator = first 8 bytes = `sha256("account:TypeName")[0..8]`

Each type has unique discriminator → cannot be confused!

---

### 7. Closing Account Vulnerabilities

#### Revival Attack

**The Vulnerability:**
After "closing" an account by zeroing lamports, the data still exists until the transaction ends.

```rust
// VULNERABLE: Data not zeroed
**account.lamports.borrow_mut() = 0;
**recipient.lamports.borrow_mut() += lamports;
// Data is still readable!
```

**The Attack:**
```
Transaction {
    ix1: close_vulnerable(user_account)     // Get lamports
    ix2: fund(user_account, 1 lamport)      // Prevent garbage collection
    ix3: claim_rewards(user_account)        // Data still there!
}
// Repeat to drain reward pool
```

#### The Fix

```rust
// SECURE: Anchor zeros data
#[account(
    mut,
    close = recipient,  // Zeros data + transfers lamports
    has_one = owner,
)]
pub account: Account<'info, UserAccount>,
```

---

## Real-World Exploit Analysis

### Wormhole Bridge Exploit ($320M)

**Vulnerability:** Missing signer verification in signature validation.

**What Happened:**
- Wormhole verified signatures by checking a "guardian set" account
- The guardian set wasn't validated properly
- Attacker passed a fake guardian set with their own key
- Minted 120,000 wETH without depositing collateral

**Lesson:** Always validate account authenticity AND authority signatures.

### Slope Wallet Exploit ($8M)

**Vulnerability:** Private keys logged to centralized server.

**Lesson:** Never log or transmit sensitive data. Security extends beyond smart contracts.

### Cashio Infinite Mint ($52M)

**Vulnerability:** Missing account validation in collateral checking.

**What Happened:**
- Protocol accepted "collateral" accounts without proper validation
- Attacker created fake collateral accounts
- Minted unlimited stablecoin without real backing

**Lesson:** Every account input must be validated for ownership AND relationship.

---

## Security Testing Strategies

### 1. Fuzzing Inputs

Test edge cases for arithmetic:
```rust
#[test]
fn test_overflow() {
    // Test with u64::MAX
    // Test with 0
    // Test boundary values
}
```

### 2. Authority Manipulation

Try calling instructions with:
- Wrong signer
- No signer
- Different authority account

### 3. Account Substitution

Pass accounts that:
- Belong to different users
- Have different types
- Are uninitialized
- Are owned by wrong program

### 4. Transaction Composition

Test multi-instruction transactions:
- Close then revive
- Initialize then reinitialize
- Concurrent operations

---

## Audit Checklist

### Before Every Instruction

- [ ] All authorities checked with `Signer`
- [ ] All PDAs validated with `seeds` + `bump`
- [ ] All account relationships validated with `has_one`
- [ ] All external accounts validated for owner/type

### Arithmetic

- [ ] All addition uses `checked_add`
- [ ] All subtraction uses `checked_sub`
- [ ] All multiplication uses `checked_mul`
- [ ] All division handles zero
- [ ] All casts use `try_into()`

### CPI

- [ ] All external programs validated
- [ ] Signer seeds never passed to unvalidated programs
- [ ] Token program validated with `Program<'info, Token>`

### State Management

- [ ] All initialization uses `init` constraint
- [ ] All closing uses `close` constraint
- [ ] Discriminators handled by `Account<>` type
- [ ] No raw byte manipulation of account data

### Business Logic

- [ ] Access control enforced on all sensitive operations
- [ ] State transitions validated
- [ ] No reentrancy vulnerabilities
- [ ] All error conditions handled

---

## Conclusion

Solana program security comes down to one principle: **Never trust input.**

Every account passed to your program could be malicious. Every number could overflow. Every external program could be fake.

Anchor provides strong defaults, but understanding *why* patterns are dangerous helps you:
- Recognize vulnerabilities in code review
- Design secure systems from the start
- Avoid subtle mistakes that Anchor can't catch

**Remember:** The most devastating exploits often come from the simplest mistakes. A missing `Signer` constraint. An unchecked addition. A raw account read.

Build secure. Validate everything. Test edge cases.

---

*This guide is part of the Solana Security Patterns repository. For code examples of each vulnerability, see the program directories.*
