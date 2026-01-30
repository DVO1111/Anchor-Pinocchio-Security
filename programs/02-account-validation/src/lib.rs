//! # Account Validation & Owner Check Vulnerability
//! 
//! ## Overview
//! This module demonstrates vulnerabilities related to insufficient account validation:
//! - Missing owner checks (accepting accounts owned by wrong programs)
//! - Missing PDA seed validation
//! - Accepting arbitrary accounts as trusted state
//! 
//! ## The Attack
//! Without proper validation, attackers can:
//! - Pass fake accounts with malicious data
//! - Substitute accounts from other programs
//! - Bypass business logic by providing crafted account data
//! 
//! ## Why This Matters
//! Solana's account model means programs receive accounts as input.
//! The program MUST validate every account is what it claims to be.

use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnT");

#[program]
pub mod account_validation {
    use super::*;

    // ============================================================================
    // VULNERABILITY 1: MISSING OWNER CHECK
    // ============================================================================

    /// VULNERABLE: Does not verify the pool account is owned by this program.
    /// 
    /// ## What's Wrong?
    /// An attacker can create a fake account with arbitrary data and pass it
    /// as the "pool" account. Since we don't verify the owner, the program
    /// trusts whatever data is in the account.
    /// 
    /// ## Attack Scenario:
    /// 1. Attacker creates their own account with System Program as owner
    /// 2. Attacker writes data that matches Pool struct layout
    /// 3. Attacker sets total_deposited to 0 and reward_rate to 1000000
    /// 4. Attacker claims massive rewards from a fake pool state
    pub fn claim_rewards_vulnerable(ctx: Context<ClaimRewardsVulnerable>) -> Result<()> {
        // DANGER: We're reading from an unvalidated account!
        // The pool_info data could be completely fabricated by an attacker
        let pool_info = &ctx.accounts.pool_info;
        let data = pool_info.try_borrow_data()?;
        
        // Skip discriminator, parse as if it's a Pool
        // Attacker controls this data entirely!
        let reward_rate = u64::from_le_bytes(data[8+32+8..8+32+8+8].try_into().unwrap());
        
        msg!("VULNERABLE: Claiming with reward_rate: {}", reward_rate);
        // Would transfer reward_rate tokens to user...
        
        Ok(())
    }

    /// SECURE: Uses Anchor's Account<> wrapper which validates:
    /// 1. Account owner matches the program ID
    /// 2. Account data deserializes correctly
    /// 3. Account discriminator is correct
    pub fn claim_rewards_secure(ctx: Context<ClaimRewardsSecure>) -> Result<()> {
        let pool = &ctx.accounts.pool;
        
        // SECURE: pool is guaranteed to be:
        // - Owned by this program
        // - Correctly deserialized
        // - Has valid discriminator
        msg!("SECURE: Claiming with reward_rate: {}", pool.reward_rate);
        
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 2: MISSING PDA VALIDATION
    // ============================================================================

    /// VULNERABLE: Does not validate PDA seeds.
    /// 
    /// ## What's Wrong?
    /// The config account should be a PDA derived from specific seeds.
    /// Without seed validation, attacker can pass ANY account as config.
    /// 
    /// ## Attack Scenario:
    /// 1. Protocol has config PDA with fee_bps = 100 (1%)
    /// 2. Attacker creates fake config account with fee_bps = 0
    /// 3. Attacker swaps tokens paying 0% fee instead of 1%
    pub fn swap_vulnerable(ctx: Context<SwapVulnerable>, amount: u64) -> Result<()> {
        // DANGER: config could be any account!
        let config_data = ctx.accounts.config.try_borrow_data()?;
        let fee_bps = u16::from_le_bytes(config_data[8+32..8+32+2].try_into().unwrap());
        
        let fee = (amount as u128 * fee_bps as u128 / 10000) as u64;
        msg!("VULNERABLE: Swap {} with fee {} ({}bps)", amount, fee, fee_bps);
        
        Ok(())
    }

    /// SECURE: Validates PDA with seeds constraint.
    /// 
    /// ## What's Fixed?
    /// The `seeds` and `bump` constraints ensure:
    /// 1. Account address matches expected PDA derivation
    /// 2. Cannot be substituted with arbitrary accounts
    /// 3. Deterministic and verifiable
    pub fn swap_secure(ctx: Context<SwapSecure>, amount: u64) -> Result<()> {
        let config = &ctx.accounts.config;
        
        // SECURE: config is validated PDA
        let fee = (amount as u128 * config.fee_bps as u128 / 10000) as u64;
        msg!("SECURE: Swap {} with fee {} ({}bps)", amount, fee, config.fee_bps);
        
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 3: ACCOUNT SUBSTITUTION IN RELATIONSHIPS
    // ============================================================================

    /// VULNERABLE: Does not verify token account belongs to user.
    /// 
    /// ## What's Wrong?
    /// The user_token_account is not validated to belong to the user.
    /// Attacker can pass victim's token account and steal their tokens.
    /// 
    /// ## Attack Scenario:
    /// 1. Attacker calls deposit with their signer
    /// 2. Passes victim's token account as user_token_account
    /// 3. Victim's tokens get transferred to pool
    /// 4. Attacker's user_deposit account gets credited
    pub fn deposit_vulnerable(ctx: Context<DepositVulnerable>, amount: u64) -> Result<()> {
        // DANGER: No check that user_token_account.owner == user.key()
        msg!("VULNERABLE: Depositing {} tokens", amount);
        // Would transfer from user_token_account to pool...
        // Attacker could pass victim's token account!
        
        Ok(())
    }

    /// SECURE: Validates token account ownership with constraint.
    /// 
    /// ## What's Fixed?
    /// The `constraint` ensures the token account's owner matches the signer.
    /// For SPL tokens, also validates the mint matches expected mint.
    pub fn deposit_secure(ctx: Context<DepositSecure>, amount: u64) -> Result<()> {
        // SECURE: user_token_account is validated to belong to user
        msg!("SECURE: Depositing {} tokens from verified account", amount);
        
        Ok(())
    }

    // ============================================================================
    // INITIALIZATION
    // ============================================================================

    pub fn initialize_pool(ctx: Context<InitializePool>, reward_rate: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total_deposited = 0;
        pool.reward_rate = reward_rate;
        pool.bump = ctx.bumps.pool;
        Ok(())
    }

    pub fn initialize_config(ctx: Context<InitializeConfig>, fee_bps: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.fee_bps = fee_bps;
        config.bump = ctx.bumps.config;
        Ok(())
    }
}

// ============================================================================
// VULNERABLE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct ClaimRewardsVulnerable<'info> {
    /// VULNERABLE: UncheckedAccount allows ANY account to be passed!
    /// 
    /// Problems:
    /// 1. No owner check - could be owned by any program
    /// 2. No discriminator check - could be any data format
    /// 3. No deserialization validation - trusting raw bytes
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub pool_info: UncheckedAccount<'info>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct SwapVulnerable<'info> {
    /// VULNERABLE: No PDA seed validation!
    /// 
    /// Even though we expect this to be a PDA, we don't verify it.
    /// Attacker can pass any account with matching data layout.
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub config: UncheckedAccount<'info>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct DepositVulnerable<'info> {
    /// CHECK: Intentionally insecure
    pub pool: UncheckedAccount<'info>,
    
    /// VULNERABLE: No ownership validation!
    /// 
    /// We don't verify this token account belongs to the user.
    /// Attacker can pass anyone's token account.
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub user_token_account: UncheckedAccount<'info>,
    
    pub user: Signer<'info>,
}

// ============================================================================
// SECURE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct ClaimRewardsSecure<'info> {
    /// SECURE: Account<> wrapper provides:
    /// 
    /// 1. Owner Check: Verifies account is owned by this program
    /// 2. Discriminator Check: Validates the 8-byte discriminator
    /// 3. Deserialization: Safely deserializes into Pool struct
    /// 4. Type Safety: Compile-time guarantee of correct type
    #[account(
        seeds = [b"pool", pool.authority.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct SwapSecure<'info> {
    /// SECURE: PDA validation with seeds constraint
    /// 
    /// The `seeds` constraint ensures:
    /// 1. Address is derived from ["config"] seed
    /// 2. Cannot be any arbitrary account
    /// 3. Deterministic - same seeds always produce same address
    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct DepositSecure<'info> {
    #[account(
        seeds = [b"pool", pool.authority.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,
    
    /// SECURE: Token account with ownership validation
    /// 
    /// Constraints ensure:
    /// 1. `token::authority` - Token account owner is the user
    /// 2. `token::mint` - Token account holds correct mint
    /// 3. Anchor's TokenAccount validates it's a valid SPL token account
    #[account(
        mut,
        token::authority = user,
        // token::mint = pool.deposit_mint, // Would add in real implementation
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    
    pub user: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(reward_rate: u64)]
pub struct InitializePool<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool", authority.key().as_ref()],
        bump
    )]
    pub pool: Account<'info, Pool>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
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

// ============================================================================
// STATE
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub authority: Pubkey,
    pub total_deposited: u64,
    pub reward_rate: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub fee_bps: u16,
    pub bump: u8,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum ValidationError {
    #[msg("Account owner validation failed")]
    InvalidOwner,
    #[msg("PDA derivation mismatch")]
    InvalidPDA,
    #[msg("Token account does not belong to user")]
    TokenAccountOwnerMismatch,
}

// ============================================================================
// SECURITY CHECKLIST FOR ACCOUNT VALIDATION
// ============================================================================
//
// - Use Account<'info, T> instead of UncheckedAccount for program state
// - Validate PDA seeds with `seeds` and `bump` constraints
// - Verify token account ownership with `token::authority`
// - Check token mint with `token::mint` constraint
// - Use `has_one` to validate account relationships
// - Validate program accounts with Program<'info, T>
// - Add explicit constraints for business logic validation
//
// ============================================================================
