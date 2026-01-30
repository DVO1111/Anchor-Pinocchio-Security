//! # Missing Signer Check Vulnerability
//! 
//! ## Overview
//! This module demonstrates one of the most common vulnerabilities in Solana programs:
//! failing to verify that an account has actually signed a transaction.
//! 
//! ## The Attack
//! Without proper signer verification, an attacker can:
//! - Withdraw funds from any vault by passing someone else's authority account
//! - Modify state belonging to other users
//! - Bypass authorization entirely
//! 
//! ## Real-World Impact
//! This vulnerability has led to millions of dollars in losses across DeFi protocols.
//! Notable examples include the Wormhole bridge exploit where missing validation
//! allowed attackers to mint tokens without proper authorization.

use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod missing_signer_check {
    use super::*;

    // ============================================================================
    // VULNERABLE INSTRUCTION
    // ============================================================================
    
    /// VULNERABLE: This instruction does NOT verify that `authority` signed the transaction.
    /// 
    /// ## What's Wrong?
    /// The `authority` account is passed without the `Signer` constraint. This means:
    /// - Anyone can pass ANY pubkey as the authority
    /// - The program trusts the authority field without verification
    /// - An attacker can drain any vault by passing the vault owner's pubkey
    /// 
    /// ## Attack Scenario:
    /// 1. Attacker finds a vault with funds owned by victim_pubkey
    /// 2. Attacker calls withdraw_vulnerable with:
    ///    - authority = victim_pubkey (NOT signing)
    ///    - vault = victim's vault
    ///    - recipient = attacker's account
    /// 3. Funds transfer to attacker because authority is never verified as signer
    pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // DANGER: We check if authority matches, but NEVER check if they signed!
        // This is security theater - the check is meaningless without signature verification
        require!(
            vault.authority == ctx.accounts.authority.key(),
            CustomError::Unauthorized
        );

        // Transfer funds (would succeed for any attacker who knows the authority pubkey)
        let transfer_amount = amount.min(vault.balance);
        vault.balance = vault.balance.checked_sub(transfer_amount).unwrap();
        
        // In real code, this would transfer lamports to recipient
        msg!("VULNERABLE: Transferred {} lamports", transfer_amount);
        
        Ok(())
    }

    // ============================================================================
    // SECURE INSTRUCTION
    // ============================================================================
    
    /// SECURE: This instruction properly verifies the authority signature.
    /// 
    /// ## What's Fixed?
    /// The `authority` account uses the `Signer` constraint which:
    /// - Anchor automatically verifies the account signed the transaction
    /// - The instruction fails immediately if signature is missing
    /// - No additional code needed - Anchor handles verification
    /// 
    /// ## Defense in Depth:
    /// We also keep the authority pubkey check as a secondary verification,
    /// ensuring the signer is actually the vault's designated authority.
    pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // SECURE: authority.key() check combined with Signer constraint
        // The Signer constraint (in account struct) ensures they actually signed
        // This check ensures the signer is the CORRECT authority for this vault
        require!(
            vault.authority == ctx.accounts.authority.key(),
            CustomError::Unauthorized
        );

        let transfer_amount = amount.min(vault.balance);
        vault.balance = vault.balance.checked_sub(transfer_amount).unwrap();
        
        msg!("SECURE: Transferred {} lamports", transfer_amount);
        
        Ok(())
    }

    /// Initialize a vault for demonstration
    pub fn initialize_vault(ctx: Context<InitializeVault>, initial_balance: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = initial_balance;
        vault.bump = ctx.bumps.vault;
        Ok(())
    }
}

// ============================================================================
// VULNERABLE ACCOUNT STRUCTURE
// ============================================================================

#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// VULNERABLE: Missing `Signer` constraint!
    /// 
    /// CHECK: This is intentionally insecure for demonstration.
    /// The account is marked as UncheckedAccount which bypasses Anchor's safety checks.
    /// In production, NEVER use UncheckedAccount for authority accounts.
    /// 
    /// What an attacker sees:
    /// - Just need to know the victim's pubkey
    /// - No signature required
    /// - Can impersonate any authority
    pub authority: UncheckedAccount<'info>,
    
    /// CHECK: Recipient account for withdrawn funds
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

// ============================================================================
// SECURE ACCOUNT STRUCTURE  
// ============================================================================

#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// SECURE: The `Signer` constraint ensures this account signed the transaction.
    /// 
    /// How Anchor enforces this:
    /// 1. Anchor checks transaction signatures before instruction executes
    /// 2. If authority's pubkey is not in the transaction's signer list, it fails
    /// 3. Error: "Signature verification failed" - clear and immediate
    /// 
    /// This single constraint prevents the entire class of missing signer attacks.
    pub authority: Signer<'info>,
    
    /// CHECK: Recipient account for withdrawn funds
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(initial_balance: u64)]
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

// ============================================================================
// STATE
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Vault {
    /// The only pubkey authorized to withdraw from this vault
    pub authority: Pubkey,
    /// Current balance in the vault
    pub balance: u64,
    /// PDA bump seed
    pub bump: u8,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum CustomError {
    #[msg("You are not authorized to perform this action")]
    Unauthorized,
}

// ============================================================================
// COMPARISON TABLE
// ============================================================================
//
// | Aspect              | Vulnerable                    | Secure                      |
// |---------------------|-------------------------------|----------------------------|
// | Authority Type      | UncheckedAccount              | Signer                      |
// | Signature Check     | None                          | Automatic by Anchor         |
// | Attack Surface      | Anyone can impersonate        | Only actual signer          |
// | Runtime Behavior    | Silently accepts any pubkey   | Fails if not signed         |
// | Code Complexity     | Same                          | Same (constraint only)      |
//
// ============================================================================
