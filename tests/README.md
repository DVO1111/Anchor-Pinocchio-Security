# Solana Security Patterns - Test Suite

This directory would contain integration tests for demonstrating both the vulnerabilities and their fixes.

## Test Structure

```
tests/
├── 01-missing-signer-check.ts
├── 02-account-validation.ts
├── 03-integer-overflow.ts
├── 04-arbitrary-cpi.ts
├── 05-reinitialization.ts
├── 06-type-cosplay.ts
└── 07-closing-accounts.ts
```

## Test Philosophy

Each test file would demonstrate:

1. **Vulnerable Path** - Shows how the exploit works
2. **Secure Path** - Shows the fix prevents the exploit

### Example Test Structure

```typescript
describe("missing-signer-check", () => {
  describe("vulnerable instruction", () => {
    it("allows withdrawal without authority signature", async () => {
      // Setup: Create vault owned by Alice
      // Attack: Bob calls withdraw_vulnerable with Alice's pubkey
      // Expect: Withdrawal succeeds (vulnerability!)
    });
  });

  describe("secure instruction", () => {
    it("rejects withdrawal without authority signature", async () => {
      // Setup: Create vault owned by Alice
      // Attack: Bob calls withdraw_secure with Alice's pubkey
      // Expect: Transaction fails with signer error
    });

    it("allows withdrawal with proper signature", async () => {
      // Setup: Create vault owned by Alice
      // Action: Alice calls withdraw_secure
      // Expect: Withdrawal succeeds
    });
  });
});
```

## Running Tests

```bash
# Build programs
anchor build

# Run all tests
anchor test

# Run specific test
anchor test -- --grep "missing-signer-check"
```

## Note on Test Implementation

Full test implementations would require:
- Local validator setup
- Account creation helpers
- Transaction building utilities

These tests are educational and demonstrate the attack vectors. In production, you would implement comprehensive test coverage for all paths.
