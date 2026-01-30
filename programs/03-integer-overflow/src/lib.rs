//! # Integer Overflow/Underflow Vulnerabilities
//! 
//! ## Overview
//! Integer arithmetic in Rust can overflow or underflow when values exceed
//! their type's bounds. In release builds, this wraps around silently,
//! leading to unexpected behavior.
//! 
//! ## The Problem
//! - u64::MAX + 1 = 0 (overflow wraps to minimum)
//! - 0u64 - 1 = u64::MAX (underflow wraps to maximum)
//! - Multiplication can overflow with smaller values than expected
//! 
//! ## Real-World Impact
//! Integer overflow vulnerabilities have caused:
//! - Token minting exploits (mint near-infinite tokens)
//! - Withdrawal exploits (underflow to get more than deposited)
//! - Price manipulation in AMMs
//! 
//! ## Rust's Behavior
//! - Debug builds: Panic on overflow
//! - Release builds: Silent wraparound (DANGEROUS!)
//! - Must use explicit checked/saturating arithmetic for safety

use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnU");

#[program]
pub mod integer_overflow {
    use super::*;

    // ============================================================================
    // VULNERABILITY 1: ADDITION OVERFLOW
    // ============================================================================

    /// VULNERABLE: Direct addition can overflow silently in release builds.
    /// 
    /// ## What's Wrong?
    /// When `vault.balance + amount` exceeds u64::MAX, it wraps around to a 
    /// small number. User deposits large amount but vault shows tiny balance.
    /// 
    /// ## Attack Scenario:
    /// 1. Vault has balance = u64::MAX - 100
    /// 2. Attacker deposits 200
    /// 3. Expected: balance = u64::MAX - 100 + 200 = u64::MAX + 100
    /// 4. Actual: balance = 99 (wrapped around!)
    /// 5. Other users' funds are now "lost" in the overflow
    pub fn deposit_vulnerable(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // DANGER: Silent overflow in release builds!
        // u64::MAX + 1 = 0
        vault.total_deposits = vault.total_deposits + amount;
        
        msg!("VULNERABLE: Deposited {}, total: {}", amount, vault.total_deposits);
        Ok(())
    }

    /// SECURE: Uses checked arithmetic that returns None on overflow.
    pub fn deposit_secure(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // SECURE: checked_add returns None if overflow would occur
        vault.total_deposits = vault.total_deposits
            .checked_add(amount)
            .ok_or(MathError::Overflow)?;
        
        msg!("SECURE: Deposited {}, total: {}", amount, vault.total_deposits);
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 2: SUBTRACTION UNDERFLOW
    // ============================================================================

    /// VULNERABLE: Subtraction can underflow, allowing withdrawal of more than balance.
    /// 
    /// ## What's Wrong?
    /// When `user_balance - amount` goes below 0, it wraps to u64::MAX.
    /// This is the classic "infinite money" exploit.
    /// 
    /// ## Attack Scenario:
    /// 1. User has balance = 100
    /// 2. User withdraws 101 (more than balance)
    /// 3. Expected: Should fail or return 100
    /// 4. Actual: balance = 100 - 101 = u64::MAX (underflow!)
    /// 5. User now has near-infinite balance
    pub fn withdraw_vulnerable(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        
        // DANGER: Underflow wraps to u64::MAX!
        // 100 - 101 = 18446744073709551615
        user_account.balance = user_account.balance - amount;
        
        msg!("VULNERABLE: Withdrew {}, remaining: {}", amount, user_account.balance);
        Ok(())
    }

    /// SECURE: Uses checked subtraction that fails on underflow.
    pub fn withdraw_secure(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        
        // SECURE: checked_sub returns None if underflow would occur
        user_account.balance = user_account.balance
            .checked_sub(amount)
            .ok_or(MathError::InsufficientFunds)?;
        
        msg!("SECURE: Withdrew {}, remaining: {}", amount, user_account.balance);
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 3: MULTIPLICATION OVERFLOW
    // ============================================================================

    /// VULNERABLE: Multiplication overflows much faster than expected.
    /// 
    /// ## What's Wrong?
    /// u64::MAX ≈ 18.4 × 10^18
    /// sqrt(u64::MAX) ≈ 4.3 × 10^9
    /// Any two numbers > 4.3B will overflow when multiplied!
    /// 
    /// ## Attack Scenario (Price Calculation):
    /// 1. price = 5_000_000_000 (5B, within u64 range)
    /// 2. quantity = 4_000_000_000 (4B, within u64 range)
    /// 3. total = price * quantity = 20 × 10^18 (exceeds u64::MAX!)
    /// 4. Actual: total wraps to small number
    /// 5. User buys items for nearly nothing
    pub fn calculate_price_vulnerable(ctx: Context<PriceCalculation>, quantity: u64) -> Result<()> {
        let config = &ctx.accounts.config;
        
        // DANGER: Multiplication overflow!
        // Even "reasonable" numbers can overflow
        let total_price = config.price_per_unit * quantity;
        
        msg!("VULNERABLE: {} units at {} each = {} total", 
            quantity, config.price_per_unit, total_price);
        Ok(())
    }

    /// SECURE: Uses checked multiplication.
    pub fn calculate_price_secure(ctx: Context<PriceCalculation>, quantity: u64) -> Result<()> {
        let config = &ctx.accounts.config;
        
        // SECURE: checked_mul returns None on overflow
        let total_price = config.price_per_unit
            .checked_mul(quantity)
            .ok_or(MathError::Overflow)?;
        
        msg!("SECURE: {} units at {} each = {} total", 
            quantity, config.price_per_unit, total_price);
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 4: CASTING TRUNCATION
    // ============================================================================

    /// VULNERABLE: Casting between integer types can truncate values.
    /// 
    /// ## What's Wrong?
    /// Casting u64 to u32 silently drops the high 32 bits.
    /// This can turn large values into small ones.
    /// 
    /// ## Attack Scenario:
    /// 1. User requests withdrawal of 4_294_967_296 + 100 (u64)
    /// 2. Cast to u32: only 100 is recorded
    /// 3. User withdraws 4.3B tokens but only 100 is debited
    pub fn record_withdrawal_vulnerable(
        ctx: Context<RecordWithdrawal>, 
        amount: u64
    ) -> Result<()> {
        let record = &mut ctx.accounts.record;
        
        // DANGER: Truncation! High bits are silently dropped
        // 4_294_967_396 as u32 = 100
        record.last_withdrawal = amount as u32;
        
        msg!("VULNERABLE: Recorded withdrawal of {} (truncated)", record.last_withdrawal);
        Ok(())
    }

    /// SECURE: Uses try_into() which fails on overflow.
    pub fn record_withdrawal_secure(
        ctx: Context<RecordWithdrawal>, 
        amount: u64
    ) -> Result<()> {
        let record = &mut ctx.accounts.record;
        
        // SECURE: try_into() returns Err if value doesn't fit
        record.last_withdrawal = amount
            .try_into()
            .map_err(|_| MathError::CastOverflow)?;
        
        msg!("SECURE: Recorded withdrawal of {}", record.last_withdrawal);
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 5: DIVISION PRECISION LOSS
    // ============================================================================

    /// VULNERABLE: Integer division loses precision, can be exploited.
    /// 
    /// ## What's Wrong?
    /// Integer division rounds down, potentially to zero.
    /// This can be exploited to avoid fees or manipulate rewards.
    /// 
    /// ## Attack Scenario:
    /// 1. Fee is 1% (100 basis points out of 10000)
    /// 2. User transfers 99 tokens
    /// 3. fee = 99 * 100 / 10000 = 9900 / 10000 = 0 (rounded down!)
    /// 4. User pays zero fees by splitting into small transactions
    pub fn calculate_fee_vulnerable(ctx: Context<FeeCalculation>, amount: u64) -> Result<u64> {
        let config = &ctx.accounts.config;
        
        // DANGER: Division rounds down, small amounts = 0 fee
        let fee = amount * config.fee_bps as u64 / 10000;
        
        msg!("VULNERABLE: Fee on {} = {} (may be 0!)", amount, fee);
        Ok(fee)
    }

    /// SECURE: Uses ceiling division to ensure minimum fee.
    pub fn calculate_fee_secure(ctx: Context<FeeCalculation>, amount: u64) -> Result<u64> {
        let config = &ctx.accounts.config;
        
        // SECURE: Ceiling division ensures non-zero fee for any transfer
        // Formula: (a + b - 1) / b = ceiling(a / b)
        let numerator = amount
            .checked_mul(config.fee_bps as u64)
            .ok_or(MathError::Overflow)?;
        
        let fee = numerator
            .checked_add(10000 - 1)
            .ok_or(MathError::Overflow)?
            .checked_div(10000)
            .ok_or(MathError::DivisionByZero)?;
        
        // Alternatively, ensure minimum fee
        let min_fee = 1u64;
        let final_fee = fee.max(min_fee);
        
        msg!("SECURE: Fee on {} = {} (min {})", amount, final_fee, min_fee);
        Ok(final_fee)
    }

    // ============================================================================
    // INITIALIZATION
    // ============================================================================

    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.total_deposits = 0;
        vault.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn initialize_user_account(ctx: Context<InitializeUserAccount>, initial_balance: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        user_account.owner = ctx.accounts.owner.key();
        user_account.balance = initial_balance;
        user_account.bump = ctx.bumps.user_account;
        Ok(())
    }

    pub fn initialize_config(ctx: Context<InitializeConfig>, price: u64, fee_bps: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.price_per_unit = price;
        config.fee_bps = fee_bps;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn initialize_record(ctx: Context<InitializeRecord>) -> Result<()> {
        let record = &mut ctx.accounts.record;
        record.user = ctx.accounts.user.key();
        record.last_withdrawal = 0;
        record.bump = ctx.bumps.record;
        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"user", user_account.owner.as_ref()],
        bump = user_account.bump,
        has_one = owner,
    )]
    pub user_account: Account<'info, UserAccount>,
    
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct PriceCalculation<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct RecordWithdrawal<'info> {
    #[account(
        mut,
        seeds = [b"record", user.key().as_ref()],
        bump = record.bump,
    )]
    pub record: Account<'info, WithdrawalRecord>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct FeeCalculation<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeUserAccount<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + UserAccount::INIT_SPACE,
        seeds = [b"user", owner.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + Config::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeRecord<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + WithdrawalRecord::INIT_SPACE,
        seeds = [b"record", user.key().as_ref()],
        bump
    )]
    pub record: Account<'info, WithdrawalRecord>,
    
    #[account(mut)]
    pub user: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

// ============================================================================
// STATE
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub total_deposits: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub price_per_unit: u64,
    pub fee_bps: u16,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct WithdrawalRecord {
    pub user: Pubkey,
    pub last_withdrawal: u32,  // Intentionally u32 to show truncation
    pub bump: u8,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum MathError {
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow - insufficient funds")]
    InsufficientFunds,
    #[msg("Division by zero")]
    DivisionByZero,
    #[msg("Cast overflow - value too large for target type")]
    CastOverflow,
}

// ============================================================================
// SAFE MATH HELPER FUNCTIONS
// ============================================================================

/// Collection of safe math utilities
pub mod safe_math {
    use super::*;

    /// Safely add two u64 values, returning error on overflow
    pub fn safe_add(a: u64, b: u64) -> Result<u64> {
        a.checked_add(b).ok_or_else(|| error!(MathError::Overflow))
    }

    /// Safely subtract two u64 values, returning error on underflow
    pub fn safe_sub(a: u64, b: u64) -> Result<u64> {
        a.checked_sub(b).ok_or_else(|| error!(MathError::InsufficientFunds))
    }

    /// Safely multiply two u64 values, returning error on overflow
    pub fn safe_mul(a: u64, b: u64) -> Result<u64> {
        a.checked_mul(b).ok_or_else(|| error!(MathError::Overflow))
    }

    /// Safely divide, returning error on division by zero
    pub fn safe_div(a: u64, b: u64) -> Result<u64> {
        a.checked_div(b).ok_or_else(|| error!(MathError::DivisionByZero))
    }

    /// Ceiling division: ceil(a / b)
    pub fn ceil_div(a: u64, b: u64) -> Result<u64> {
        if b == 0 {
            return Err(error!(MathError::DivisionByZero));
        }
        Ok((a + b - 1) / b)
    }

    /// Calculate percentage with basis points (1 bp = 0.01%)
    /// Returns ceil(amount * bps / 10000) to prevent zero fees
    pub fn calculate_bps_fee(amount: u64, bps: u16) -> Result<u64> {
        let numerator = safe_mul(amount, bps as u64)?;
        ceil_div(numerator, 10000)
    }
}

// ============================================================================
// COMPARISON TABLE
// ============================================================================
//
// | Operation      | Vulnerable            | Secure                           |
// |----------------|----------------------|----------------------------------|
// | Addition       | a + b                 | a.checked_add(b).ok_or(err)?    |
// | Subtraction    | a - b                 | a.checked_sub(b).ok_or(err)?    |
// | Multiplication | a * b                 | a.checked_mul(b).ok_or(err)?    |
// | Division       | a / b                 | a.checked_div(b).ok_or(err)?    |
// | Casting        | value as u32          | value.try_into().ok_or(err)?    |
// | Power          | base.pow(exp)         | base.checked_pow(exp).ok_or()?  |
//
// ============================================================================
