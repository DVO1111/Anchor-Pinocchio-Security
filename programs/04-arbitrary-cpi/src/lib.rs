//! # Arbitrary CPI (Cross-Program Invocation) Vulnerabilities
//! 
//! ## Overview
//! Cross-Program Invocation (CPI) allows Solana programs to call other programs.
//! When the target program is not validated, attackers can substitute malicious
//! programs to steal funds, manipulate state, or bypass security checks.
//! 
//! ## The Danger
//! If your program invokes another program without verifying it's the expected
//! program, an attacker can:
//! - Provide a malicious program that returns fake success
//! - Steal tokens by substituting a fake token program
//! - Bypass verification by providing a program that always succeeds
//! 
//! ## CPI and Signer Seeds
//! When a program does CPI, it can "sign" on behalf of PDAs it controls.
//! This is safe when calling trusted programs, but dangerous with arbitrary ones.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program::invoke, system_instruction};
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnV");

#[program]
pub mod arbitrary_cpi {
    use super::*;

    // ============================================================================
    // VULNERABILITY 1: ARBITRARY PROGRAM CPI
    // ============================================================================

    /// VULNERABLE: Does not validate the program being called.
    /// 
    /// ## What's Wrong?
    /// The `target_program` is accepted without verification.
    /// An attacker can pass their own program that:
    /// - Always returns success
    /// - Ignores the actual operation
    /// - Steals funds to attacker-controlled accounts
    /// 
    /// ## Attack Scenario:
    /// 1. User wants to swap tokens through our aggregator
    /// 2. Attacker creates malicious "swap" program
    /// 3. Attacker's program takes user's tokens but gives nothing back
    /// 4. Our program sees "success" and completes normally
    pub fn swap_vulnerable<'info>(
        ctx: Context<'_, '_, '_, 'info, SwapVulnerable<'info>>,
        amount: u64,
    ) -> Result<()> {
        // DANGER: No validation that this is the real swap program!
        let swap_program = &ctx.accounts.swap_program;
        
        msg!("VULNERABLE: Calling unvalidated program {}", swap_program.key());
        
        // This would invoke whatever program was passed
        // Attacker could pass malicious program
        // invoke(
        //     &swap_instruction,
        //     &[...accounts...],
        // )?;
        
        Ok(())
    }

    /// SECURE: Validates the program ID before CPI.
    /// 
    /// ## What's Fixed?
    /// We explicitly verify the program ID matches the expected swap program.
    /// Anchor's Program<> type also provides this guarantee.
    pub fn swap_secure<'info>(
        ctx: Context<'_, '_, '_, 'info, SwapSecure<'info>>,
        amount: u64,
    ) -> Result<()> {
        // SECURE: Program<> type validates the account is the expected program
        // The constraint ensures swap_program.key() == expected_program_id
        let swap_program = &ctx.accounts.swap_program;
        
        msg!("SECURE: Calling validated program {}", swap_program.key());
        
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 2: FAKE TOKEN PROGRAM
    // ============================================================================

    /// VULNERABLE: Does not verify the token program.
    /// 
    /// ## What's Wrong?
    /// An attacker can substitute a fake token program that:
    /// - Reports success without moving tokens
    /// - Moves tokens to attacker instead of destination
    /// - Mints new tokens out of thin air
    /// 
    /// ## Attack Scenario:
    /// 1. Attacker creates fake "token program"
    /// 2. Fake program's transfer instruction is a no-op
    /// 3. Attacker calls our withdraw with fake token program
    /// 4. Our vault state updates, but tokens don't actually move
    /// 5. Attacker repeats to drain vault
    pub fn transfer_tokens_vulnerable(
        ctx: Context<TransferVulnerable>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // DANGER: We don't verify this is the real Token Program!
        // Attacker can pass fake program that doesn't actually transfer
        msg!("VULNERABLE: Using unvalidated token program");
        
        // Update state as if transfer succeeded
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        
        // CPI to potentially fake token program would happen here
        
        Ok(())
    }

    /// SECURE: Uses Anchor's Program<'info, Token> type.
    /// 
    /// ## What's Fixed?
    /// The Program<'info, Token> type automatically verifies:
    /// 1. Account is executable
    /// 2. Account key matches Token Program ID
    /// 3. Cannot be substituted with fake program
    pub fn transfer_tokens_secure(
        ctx: Context<TransferSecure>,
        amount: u64,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // SECURE: token_program is validated as Token Program
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };
        
        let seeds = &[
            b"vault_authority".as_ref(),
            &[ctx.accounts.vault.vault_authority_bump],
        ];
        let signer_seeds = &[&seeds[..]];
        
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        
        // SECURE: This CPI is to the validated Token Program
        token::transfer(cpi_ctx, amount)?;
        
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        
        msg!("SECURE: Transferred {} tokens via validated Token Program", amount);
        
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 3: ARBITRARY CPI WITH SIGNER SEEDS
    // ============================================================================

    /// VULNERABLE: Passes PDA signer seeds to arbitrary program.
    /// 
    /// ## What's Wrong?
    /// When we do CPI with signer seeds, we're letting the called program
    /// act as our PDA. If we don't validate the program, it can:
    /// - Transfer tokens from our PDA
    /// - Modify our PDA's data
    /// - Close our PDA and steal lamports
    /// 
    /// ## Attack Scenario:
    /// 1. Our protocol has a treasury PDA with funds
    /// 2. Attacker passes malicious program as "reward_program"
    /// 3. We CPI to malicious program, signing with treasury seeds
    /// 4. Malicious program transfers all treasury funds to attacker
    pub fn distribute_rewards_vulnerable<'info>(
        ctx: Context<'_, '_, '_, 'info, DistributeRewardsVulnerable<'info>>,
    ) -> Result<()> {
        msg!("VULNERABLE: About to CPI with signer seeds to arbitrary program");
        
        // DANGER: We're giving our PDA's signing authority to unknown program!
        // The malicious program can do anything with our PDA
        
        // invoke_signed(
        //     &attacker_instruction,
        //     &[treasury.to_account_info(), ...],
        //     &[&[b"treasury", &[bump]]],  // Attacker gets our PDA authority!
        // )?;
        
        Ok(())
    }

    /// SECURE: Only CPI to known, validated programs.
    /// 
    /// ## What's Fixed?
    /// - Explicitly validate program ID
    /// - Use Anchor's Program<> types when possible
    /// - Never pass signer seeds to unvalidated programs
    pub fn distribute_rewards_secure<'info>(
        ctx: Context<'_, '_, '_, 'info, DistributeRewardsSecure<'info>>,
    ) -> Result<()> {
        // SECURE: Only call validated Token Program
        let seeds = &[
            b"treasury".as_ref(),
            &[ctx.accounts.treasury.bump],
        ];
        let signer_seeds = &[&seeds[..]];
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.treasury_token_account.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.treasury.to_account_info(),
        };
        
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        
        token::transfer(cpi_ctx, ctx.accounts.treasury.reward_amount)?;
        
        msg!("SECURE: Distributed rewards via validated Token Program");
        
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 4: MISSING EXECUTABLE CHECK
    // ============================================================================

    /// VULNERABLE: Does not verify account is executable.
    /// 
    /// ## What's Wrong?
    /// Even if we check the program ID, we should verify it's executable.
    /// An attacker could potentially create a non-executable account
    /// with the expected ID in some edge cases.
    pub fn call_oracle_vulnerable(
        ctx: Context<CallOracleVulnerable>,
    ) -> Result<()> {
        // DANGER: Not checking if account is executable
        let oracle = &ctx.accounts.oracle_program;
        
        msg!("VULNERABLE: Calling potentially non-executable account");
        
        Ok(())
    }

    /// SECURE: Uses constraint to verify executable.
    pub fn call_oracle_secure(
        ctx: Context<CallOracleSecure>,
    ) -> Result<()> {
        // SECURE: executable constraint and program ID check
        let oracle = &ctx.accounts.oracle_program;
        
        msg!("SECURE: Oracle program verified as executable");
        
        Ok(())
    }

    // ============================================================================
    // INITIALIZATION
    // ============================================================================

    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.vault_authority_bump = ctx.bumps.vault_authority;
        vault.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn initialize_treasury(ctx: Context<InitializeTreasury>, reward_amount: u64) -> Result<()> {
        let treasury = &mut ctx.accounts.treasury;
        treasury.admin = ctx.accounts.admin.key();
        treasury.reward_amount = reward_amount;
        treasury.bump = ctx.bumps.treasury;
        Ok(())
    }
}

// ============================================================================
// VULNERABLE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct SwapVulnerable<'info> {
    /// VULNERABLE: No program ID validation!
    /// 
    /// UncheckedAccount allows any account, including:
    /// - Non-executable accounts
    /// - Malicious programs
    /// - Wrong program IDs
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub swap_program: UncheckedAccount<'info>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferVulnerable<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: Intentionally insecure - unvalidated token program
    pub token_program: UncheckedAccount<'info>,
    
    /// CHECK: Source token account
    #[account(mut)]
    pub source: UncheckedAccount<'info>,
    
    /// CHECK: Destination token account
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct DistributeRewardsVulnerable<'info> {
    #[account(mut)]
    pub treasury: Account<'info, Treasury>,
    
    /// VULNERABLE: Arbitrary program receives PDA signer seeds!
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub reward_program: UncheckedAccount<'info>,
    
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct CallOracleVulnerable<'info> {
    /// VULNERABLE: No executable check
    /// 
    /// CHECK: Intentionally insecure
    pub oracle_program: UncheckedAccount<'info>,
}

// ============================================================================
// SECURE ACCOUNT STRUCTURES
// ============================================================================

// Note: In a real implementation, you would have the actual swap program ID
// For demonstration, we use a placeholder
// pub static SWAP_PROGRAM_ID: Pubkey = pubkey!("SwapProgramID...");

#[derive(Accounts)]
pub struct SwapSecure<'info> {
    /// SECURE: Validated program account
    /// 
    /// In production, you would use:
    /// #[account(address = SWAP_PROGRAM_ID)]
    /// pub swap_program: Program<'info, SwapProgram>,
    /// 
    /// Or with constraint:
    /// #[account(
    ///     executable,
    ///     constraint = swap_program.key() == EXPECTED_SWAP_PROGRAM @ CpiError::InvalidProgram
    /// )]
    /// 
    /// CHECK: Would be validated in production with program address constraint
    #[account(executable)]
    pub swap_program: UncheckedAccount<'info>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferSecure<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: PDA authority for vault
    #[account(
        seeds = [b"vault_authority"],
        bump = vault.vault_authority_bump,
    )]
    pub vault_authority: UncheckedAccount<'info>,
    
    /// SECURE: Program<'info, Token> validates:
    /// 1. Account is executable
    /// 2. Account key == TOKEN_PROGRAM_ID
    pub token_program: Program<'info, Token>,
    
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct DistributeRewardsSecure<'info> {
    #[account(
        seeds = [b"treasury"],
        bump = treasury.bump,
        has_one = admin,
    )]
    pub treasury: Account<'info, Treasury>,
    
    /// CHECK: Treasury token account
    #[account(mut)]
    pub treasury_token_account: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    
    /// SECURE: Only call validated Token Program
    pub token_program: Program<'info, Token>,
    
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct CallOracleSecure<'info> {
    /// SECURE: Executable constraint plus address validation
    /// 
    /// In production:
    /// #[account(
    ///     executable,
    ///     address = ORACLE_PROGRAM_ID @ CpiError::InvalidOracle
    /// )]
    #[account(executable)]
    pub oracle_program: UncheckedAccount<'info>,
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
    
    /// CHECK: Vault authority PDA
    #[account(
        seeds = [b"vault_authority"],
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeTreasury<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + Treasury::INIT_SPACE,
        seeds = [b"treasury"],
        bump
    )]
    pub treasury: Account<'info, Treasury>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

// ============================================================================
// STATE
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub vault_authority_bump: u8,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Treasury {
    pub admin: Pubkey,
    pub reward_amount: u64,
    pub bump: u8,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum CpiError {
    #[msg("Invalid program ID for CPI")]
    InvalidProgram,
    #[msg("Program is not executable")]
    NotExecutable,
    #[msg("Invalid oracle program")]
    InvalidOracle,
}

// ============================================================================
// CPI SECURITY CHECKLIST
// ============================================================================
//
// Use Program<'info, T> types for standard programs (Token, System, etc.)
// Verify program IDs with `address` constraint for custom programs
// Add `executable` constraint when using UncheckedAccount for programs
// Never pass signer seeds to unvalidated programs
// Use Anchor's CPI helpers (token::transfer, etc.) when possible
// Store expected program IDs as constants
// Be cautious with remaining_accounts - validate each one
//
// ============================================================================
