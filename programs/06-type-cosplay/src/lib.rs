//! # Type Cosplay Attack Vulnerability
//! 
//! ## Overview
//! Type cosplay occurs when an attacker passes an account of one type
//! where another type is expected. Without proper type validation,
//! the program may misinterpret the account data.
//! 
//! ## The Problem
//! If two account types have similar layouts, raw byte reading can
//! succeed but interpret the data incorrectly:
//! - User account data read as Admin account
//! - Regular vault read as reward vault
//! - Different struct fields at same byte offsets
//! 
//! ## Why This Matters
//! Type cosplay can lead to:
//! - Privilege escalation (user becomes admin)
//! - Asset theft (manipulated balances)
//! - Bypassed access controls

use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnX");

#[program]
pub mod type_cosplay {
    use super::*;

    // ============================================================================
    // VULNERABILITY 1: NO DISCRIMINATOR CHECK
    // ============================================================================

    /// VULNERABLE: Reads account data without type validation.
    /// 
    /// ## What's Wrong?
    /// The function reads raw bytes and interprets them as an AdminConfig.
    /// An attacker can pass ANY account with the right byte layout.
    /// 
    /// ## Attack Scenario (Privilege Escalation):
    /// 
    /// AdminConfig layout:
    /// | Byte Offset | Field      | Size   |
    /// |-------------|------------|--------|
    /// | 0-31        | admin      | 32     |
    /// | 32          | is_admin   | 1      |
    /// 
    /// UserAccount layout:  
    /// | Byte Offset | Field      | Size   |
    /// |-------------|------------|--------|
    /// | 0-31        | owner      | 32     |
    /// | 32-39       | balance    | 8      |
    /// 
    /// If attacker's balance = 1 (as u64), the first byte is 0x01.
    /// When read as AdminConfig, is_admin (byte 32) = 0x01 = true!
    /// 
    /// Attacker creates UserAccount with balance = 1, passes it as AdminConfig.
    pub fn admin_action_vulnerable(ctx: Context<AdminActionVulnerable>) -> Result<()> {
        let account_data = ctx.accounts.admin_config.try_borrow_data()?;
        
        // DANGER: Reading raw bytes without type validation!
        // Skip 8-byte discriminator (if present) - but attacker might not have one
        let admin_pubkey = Pubkey::try_from(&account_data[0..32]).unwrap();
        let is_admin = account_data[32] == 1;  // Just checking a byte!
        
        require!(
            ctx.accounts.signer.key() == admin_pubkey && is_admin,
            TypeCosplayError::NotAdmin
        );
        
        msg!("VULNERABLE: Admin action performed (but was it really an admin?)");
        Ok(())
    }

    /// SECURE: Uses Anchor's Account<> which validates discriminator.
    /// 
    /// ## What's Fixed?
    /// The Account<'info, AdminConfig> type:
    /// 1. Checks 8-byte discriminator matches AdminConfig
    /// 2. Verifies account is owned by this program
    /// 3. Deserializes data safely into the correct type
    /// 
    /// A UserAccount cannot be passed - discriminator won't match.
    pub fn admin_action_secure(ctx: Context<AdminActionSecure>) -> Result<()> {
        let config = &ctx.accounts.admin_config;
        
        // SECURE: config is guaranteed to be AdminConfig
        // Anchor validated discriminator and owner
        require!(
            ctx.accounts.signer.key() == config.admin,
            TypeCosplayError::NotAdmin
        );
        
        msg!("SECURE: Admin action performed by verified admin");
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 2: SAME LAYOUT, DIFFERENT MEANING
    // ============================================================================

    /// VULNERABLE: Different account types with same layout.
    /// 
    /// ## What's Wrong?
    /// UserVault and RewardVault have identical layouts.
    /// Without discriminator checks, they're interchangeable.
    /// 
    /// ## Attack Scenario:
    /// 1. Attacker creates UserVault with balance = 1000
    /// 2. Attacker passes UserVault to claim_rewards_vulnerable
    /// 3. Program thinks it's a RewardVault with 1000 rewards available
    /// 4. Attacker claims 1000 tokens from reward pool
    pub fn claim_rewards_vulnerable(ctx: Context<ClaimRewardsVulnerable>) -> Result<()> {
        let data = ctx.accounts.vault.try_borrow_data()?;
        
        // DANGER: No type check - could be UserVault or RewardVault!
        // Both have: owner (32 bytes) + balance (8 bytes)
        let _owner = Pubkey::try_from(&data[0..32]).unwrap();
        let balance = u64::from_le_bytes(data[32..40].try_into().unwrap());
        
        msg!("VULNERABLE: Claiming {} rewards (but is this really a RewardVault?)", balance);
        Ok(())
    }

    /// SECURE: Uses typed account that validates discriminator.
    pub fn claim_rewards_secure(ctx: Context<ClaimRewardsSecure>) -> Result<()> {
        let vault = &ctx.accounts.reward_vault;
        
        // SECURE: This is definitely a RewardVault
        msg!("SECURE: Claiming {} rewards from verified RewardVault", vault.balance);
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 3: MANUAL TYPE FLAG CAN BE SPOOFED
    // ============================================================================

    /// VULNERABLE: Relies on manual account_type field.
    /// 
    /// ## What's Wrong?
    /// Manual type flags can be set by anyone during account creation.
    /// Attacker creates account with spoofed account_type field.
    /// 
    /// ## Why Discriminators Are Better:
    /// - Discriminator = hash of struct name
    /// - Set by Anchor during proper initialization
    /// - Cannot be set to arbitrary values by users
    pub fn process_account_vulnerable(ctx: Context<ProcessAccountVulnerable>) -> Result<()> {
        let data = ctx.accounts.account.try_borrow_data()?;
        
        // DANGER: Manual type flag at byte 0 - can be spoofed!
        let account_type = data[0];
        
        match account_type {
            1 => {
                msg!("VULNERABLE: Processing as UserAccount");
                // User-level access
            },
            2 => {
                msg!("VULNERABLE: Processing as AdminAccount");
                // Admin-level access - attacker can reach here by setting byte 0 = 2
            },
            _ => {
                return Err(TypeCosplayError::InvalidAccountType.into());
            }
        }
        
        Ok(())
    }

    /// SECURE: Uses Anchor's type system with discriminators.
    pub fn process_user_secure(ctx: Context<ProcessUserSecure>) -> Result<()> {
        let _user = &ctx.accounts.user_account;
        msg!("SECURE: Processing verified UserAccount");
        Ok(())
    }

    pub fn process_admin_secure(ctx: Context<ProcessAdminSecure>) -> Result<()> {
        let _admin = &ctx.accounts.admin_config;
        msg!("SECURE: Processing verified AdminConfig");
        Ok(())
    }

    // ============================================================================
    // INITIALIZATION
    // ============================================================================

    pub fn initialize_admin_config(ctx: Context<InitializeAdminConfig>) -> Result<()> {
        let config = &mut ctx.accounts.admin_config;
        config.admin = ctx.accounts.admin.key();
        config.bump = ctx.bumps.admin_config;
        Ok(())
    }

    pub fn initialize_user_account(ctx: Context<InitializeUserAccount>) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        user.owner = ctx.accounts.owner.key();
        user.balance = 0;
        user.bump = ctx.bumps.user_account;
        Ok(())
    }

    pub fn initialize_reward_vault(ctx: Context<InitializeRewardVault>, initial_balance: u64) -> Result<()> {
        let vault = &mut ctx.accounts.reward_vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = initial_balance;
        vault.bump = ctx.bumps.reward_vault;
        Ok(())
    }
}

// ============================================================================
// VULNERABLE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct AdminActionVulnerable<'info> {
    /// VULNERABLE: UncheckedAccount allows any data!
    /// 
    /// No discriminator check means:
    /// - Any account with 33+ bytes works
    /// - Type confusion is possible
    /// - Attacker controls interpretation
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub admin_config: UncheckedAccount<'info>,
    
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimRewardsVulnerable<'info> {
    /// VULNERABLE: Could be UserVault or RewardVault
    /// 
    /// Both types have identical layouts:
    /// - owner/authority: Pubkey (32 bytes)
    /// - balance: u64 (8 bytes)
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub vault: UncheckedAccount<'info>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct ProcessAccountVulnerable<'info> {
    /// VULNERABLE: Manual type field can be spoofed
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub account: UncheckedAccount<'info>,
}

// ============================================================================
// SECURE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct AdminActionSecure<'info> {
    /// SECURE: Account<'info, AdminConfig> validates:
    /// 
    /// 1. Discriminator (8 bytes) matches "AdminConfig"
    /// 2. Owner is this program
    /// 3. Data deserializes correctly
    /// 
    /// Cannot be confused with UserAccount, RewardVault, etc.
    #[account(
        seeds = [b"admin_config"],
        bump = admin_config.bump,
    )]
    pub admin_config: Account<'info, AdminConfig>,
    
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimRewardsSecure<'info> {
    /// SECURE: Specifically RewardVault, not UserVault
    #[account(
        seeds = [b"reward_vault", reward_vault.authority.as_ref()],
        bump = reward_vault.bump,
    )]
    pub reward_vault: Account<'info, RewardVault>,
    
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct ProcessUserSecure<'info> {
    /// SECURE: Specifically UserAccount
    #[account(
        seeds = [b"user", user_account.owner.as_ref()],
        bump = user_account.bump,
    )]
    pub user_account: Account<'info, UserAccount>,
}

#[derive(Accounts)]
pub struct ProcessAdminSecure<'info> {
    /// SECURE: Specifically AdminConfig
    #[account(
        seeds = [b"admin_config"],
        bump = admin_config.bump,
    )]
    pub admin_config: Account<'info, AdminConfig>,
}

#[derive(Accounts)]
pub struct InitializeAdminConfig<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + AdminConfig::INIT_SPACE,
        seeds = [b"admin_config"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
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
pub struct InitializeRewardVault<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + RewardVault::INIT_SPACE,
        seeds = [b"reward_vault", authority.key().as_ref()],
        bump
    )]
    pub reward_vault: Account<'info, RewardVault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

// ============================================================================
// STATE
// ============================================================================

/// Admin configuration - only one per protocol
#[account]
#[derive(InitSpace)]
pub struct AdminConfig {
    /// The admin's public key
    pub admin: Pubkey,  // 32 bytes
    /// PDA bump
    pub bump: u8,       // 1 byte
}

/// User account for deposits
#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    /// Account owner
    pub owner: Pubkey,   // 32 bytes
    /// User's balance
    pub balance: u64,    // 8 bytes
    /// PDA bump
    pub bump: u8,        // 1 byte
}

/// Vault for reward distribution
/// Note: Same layout as UserAccount (owner/authority + balance + bump)
/// Without discriminators, these would be interchangeable!
#[account]
#[derive(InitSpace)]
pub struct RewardVault {
    /// Vault authority
    pub authority: Pubkey,  // 32 bytes
    /// Available rewards
    pub balance: u64,       // 8 bytes
    /// PDA bump
    pub bump: u8,           // 1 byte
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum TypeCosplayError {
    #[msg("Signer is not admin")]
    NotAdmin,
    #[msg("Invalid account type")]
    InvalidAccountType,
    #[msg("Account type mismatch")]
    TypeMismatch,
}

// ============================================================================
// HOW ANCHOR DISCRIMINATORS WORK
// ============================================================================
//
// Anchor generates an 8-byte discriminator for each account type:
//
// discriminator = sha256("account:<AccountName>")[0..8]
//
// For example:
// - AdminConfig  → sha256("account:AdminConfig")[0..8]  → [68, 212, ...]
// - UserAccount  → sha256("account:UserAccount")[0..8]  → [124, 45, ...]
// - RewardVault  → sha256("account:RewardVault")[0..8]  → [87, 156, ...]
//
// When Account<'info, T> deserializes:
// 1. Reads first 8 bytes from account data
// 2. Computes expected discriminator for type T
// 3. Fails if they don't match
//
// This makes type confusion impossible!
//
// ============================================================================
// TYPE CONFUSION ATTACK PATTERNS
// ============================================================================
//
// 1. PRIVILEGE ESCALATION
//    - Pass UserAccount as AdminConfig
//    - Gain admin privileges
//
// 2. ASSET THEFT
//    - Pass UserVault as RewardVault
//    - Claim rewards you don't own
//
// 3. DATA MANIPULATION
//    - Pass one account type as another
//    - Misinterpret fields (balance as bool, etc.)
//
// 4. BYPASS CHECKS
//    - Create account with spoofed type field
//    - Bypass authorization logic
//
// ============================================================================
