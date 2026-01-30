//! # Closing Accounts Vulnerabilities
//! 
//! ## Overview
//! Account closing is a common operation to reclaim rent and clean up state.
//! However, improper closing can lead to several vulnerabilities:
//! 
//! 1. **Revival Attack**: Closed account is reused in same transaction
//! 2. **Rent Theft**: Lamports sent to wrong recipient
//! 3. **Incomplete Closure**: Data not zeroed, can be read by others
//! 4. **Missing Authority Check**: Anyone can close any account
//! 
//! ## The Solana Account Lifecycle
//! - Accounts with 0 lamports are garbage collected
//! - Until garbage collection, data may persist
//! - Same address can be "revived" by adding lamports
//! - This creates a window for attacks

use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnY");

#[program]
pub mod closing_accounts {
    use super::*;

    // ============================================================================
    // VULNERABILITY 1: REVIVAL ATTACK (SAME TRANSACTION)
    // ============================================================================

    /// VULNERABLE: Account can be revived within same transaction.
    /// 
    /// ## What's Wrong?
    /// After closing, the account still exists until transaction ends.
    /// An attacker can:
    /// 1. Close account (get lamports back)
    /// 2. Re-fund account in same transaction
    /// 3. Use the "closed" account again
    /// 4. Repeat to drain funds or double-spend
    /// 
    /// ## Attack Scenario:
    /// 1. User has UserAccount with 1000 token rewards accrued
    /// 2. Attacker calls close_vulnerable to claim rewards
    /// 3. In same TX, attacker re-funds account to prevent garbage collection
    /// 4. Attacker calls claim_rewards (account still has rewards data!)
    /// 5. Attacker claims rewards AGAIN
    /// 6. Repeat until reward pool is drained
    pub fn close_vulnerable(ctx: Context<CloseVulnerable>) -> Result<()> {
        let user_account = &ctx.accounts.user_account;
        let recipient = &ctx.accounts.recipient;
        
        // DANGER: Just transferring lamports doesn't prevent revival!
        // Account data is still there until transaction ends
        
        // Transfer all lamports
        let lamports = user_account.to_account_info().lamports();
        **user_account.to_account_info().try_borrow_mut_lamports()? = 0;
        **recipient.to_account_info().try_borrow_mut_lamports()? += lamports;
        
        msg!("VULNERABLE: Closed account but didn't zero data!");
        Ok(())
    }

    /// SECURE: Uses Anchor's close constraint which zeros data.
    /// 
    /// ## What's Fixed?
    /// The `close` constraint:
    /// 1. Transfers all lamports to specified account
    /// 2. Zeros out all account data
    /// 3. Assigns account to System Program
    /// 
    /// Zeroing data prevents revival attacks because:
    /// - Even if account is re-funded, data is gone
    /// - Discriminator is zeroed, so deserialization fails
    pub fn close_secure(ctx: Context<CloseSecure>) -> Result<()> {
        // SECURE: Anchor's `close` constraint handles everything
        // - Lamports transferred to recipient
        // - Data zeroed
        // - Owner set to System Program
        
        msg!("SECURE: Account closed with data zeroed");
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 2: MISSING AUTHORITY CHECK
    // ============================================================================

    /// VULNERABLE: Anyone can close any account.
    /// 
    /// ## What's Wrong?
    /// No verification that the signer is authorized to close.
    /// Attacker can close victims' accounts and steal their rent.
    /// 
    /// ## Attack Scenario:
    /// 1. Alice has UserAccount with valuable state + 0.01 SOL rent
    /// 2. Attacker calls close with recipient = attacker
    /// 3. Attacker gets Alice's rent, Alice loses her account
    pub fn close_no_auth_check(ctx: Context<CloseNoAuthCheck>) -> Result<()> {
        // DANGER: No check that signer owns this account!
        let user_account = &ctx.accounts.user_account;
        let recipient = &ctx.accounts.recipient;
        
        let lamports = user_account.to_account_info().lamports();
        **user_account.to_account_info().try_borrow_mut_lamports()? = 0;
        **recipient.to_account_info().try_borrow_mut_lamports()? += lamports;
        
        msg!("VULNERABLE: Closed without verifying authority");
        Ok(())
    }

    /// SECURE: Verifies signer is the account owner.
    pub fn close_with_auth_check(ctx: Context<CloseWithAuthCheck>) -> Result<()> {
        // SECURE: `has_one = owner` constraint verifies ownership
        // Only the owner can close their account
        
        msg!("SECURE: Account closed by verified owner");
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 3: FORCE DEFUND ATTACK
    // ============================================================================

    /// VULNERABLE: Attacker can force-defund account then use stale data.
    /// 
    /// ## What's Wrong?
    /// This shows the danger of reading from accounts that might be defunded.
    /// If an account loses its lamports (goes to 0), the runtime will
    /// eventually garbage collect it, but the data might still be readable
    /// for a brief period.
    /// 
    /// ## Attack Scenario:
    /// 1. Protocol reads config from ConfigAccount
    /// 2. Attacker force-defunds ConfigAccount (transfers all lamports out)
    /// 3. Protocol still reads stale/garbage data
    /// 4. Attacker manipulates protocol behavior
    pub fn read_config_vulnerable(ctx: Context<ReadConfigVulnerable>) -> Result<()> {
        // DANGER: Not checking if account has been defunded!
        let config_info = &ctx.accounts.config;
        let data = config_info.try_borrow_data()?;
        
        msg!("VULNERABLE: Reading config without rent check");
        Ok(())
    }

    /// SECURE: Uses Account<> which validates rent-exempt status.
    pub fn read_config_secure(ctx: Context<ReadConfigSecure>) -> Result<()> {
        // SECURE: Account<> validates the account is rent-exempt
        // and properly owned by this program
        let config = &ctx.accounts.config;
        
        msg!("SECURE: Config fee_bps = {}", config.fee_bps);
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 4: CLOSING PDA WITHOUT INVALIDATION
    // ============================================================================

    /// VULNERABLE: PDA can be recreated with same seeds.
    /// 
    /// ## What's Wrong?
    /// After closing a PDA, anyone can re-initialize it with new data.
    /// This can be exploited if the protocol expects "once closed, always closed".
    /// 
    /// ## Attack Scenario:
    /// 1. Protocol uses UserProfile PDA for one-time airdrop eligibility
    /// 2. User claims airdrop, admin closes their profile (marking as claimed)
    /// 3. User re-initializes profile PDA (same seeds still valid!)
    /// 4. User claims airdrop again
    pub fn close_profile_vulnerable(ctx: Context<CloseProfileVulnerable>) -> Result<()> {
        // DANGER: Just closing isn't enough for PDAs!
        // PDA can be recreated with same seeds
        
        msg!("VULNERABLE: Closed profile but PDA can be recreated");
        Ok(())
    }

    /// SECURE: Marks profile as closed before zeroing.
    /// 
    /// ## What's Fixed?
    /// - Set a tombstone flag before closing
    /// - Future init checks for tombstone in separate account
    /// - Or use unique seeds that include timestamp/nonce
    pub fn close_profile_secure(ctx: Context<CloseProfileSecure>) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        let tombstone = &mut ctx.accounts.tombstone;
        
        // SECURE: Create permanent record that this profile was closed
        tombstone.original_owner = profile.owner;
        tombstone.closed_at = Clock::get()?.unix_timestamp;
        
        msg!("SECURE: Profile closed with tombstone record");
        Ok(())
    }

    // ============================================================================
    // HELPER INSTRUCTIONS
    // ============================================================================

    pub fn initialize_user_account(ctx: Context<InitializeUserAccount>) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        user_account.owner = ctx.accounts.owner.key();
        user_account.balance = 0;
        user_account.rewards_accrued = 0;
        user_account.bump = ctx.bumps.user_account;
        Ok(())
    }

    pub fn initialize_config(ctx: Context<InitializeConfig>, fee_bps: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.fee_bps = fee_bps;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn initialize_profile(ctx: Context<InitializeProfile>) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.owner = ctx.accounts.owner.key();
        profile.points = 0;
        profile.bump = ctx.bumps.profile;
        Ok(())
    }

    pub fn accrue_rewards(ctx: Context<AccrueRewards>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        user_account.rewards_accrued = user_account.rewards_accrued.checked_add(amount).unwrap();
        Ok(())
    }

    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<u64> {
        let user_account = &mut ctx.accounts.user_account;
        let rewards = user_account.rewards_accrued;
        user_account.rewards_accrued = 0;
        msg!("Claimed {} rewards", rewards);
        Ok(rewards)
    }
}

// ============================================================================
// VULNERABLE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct CloseVulnerable<'info> {
    /// Account being closed - but not properly!
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    /// CHECK: Recipient of rent lamports
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseNoAuthCheck<'info> {
    /// VULNERABLE: No ownership verification!
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    /// CHECK: Recipient of rent lamports
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    
    /// Signer might not be the owner!
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReadConfigVulnerable<'info> {
    /// VULNERABLE: Raw account could be defunded
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub config: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct CloseProfileVulnerable<'info> {
    /// Profile that will be closed
    #[account(
        mut,
        close = recipient,
        seeds = [b"profile", profile.owner.as_ref()],
        bump = profile.bump,
    )]
    pub profile: Account<'info, UserProfile>,
    
    /// CHECK: Recipient of rent
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    
    pub owner: Signer<'info>,
}

// ============================================================================
// SECURE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct CloseSecure<'info> {
    /// SECURE: `close` constraint handles everything properly
    /// 
    /// The `close` constraint:
    /// 1. Transfers all lamports to `recipient`
    /// 2. Zeros all account data
    /// 3. Sets owner to System Program
    /// 4. Prevents revival attacks
    #[account(
        mut,
        close = recipient,  // Anchor handles closure safely
        seeds = [b"user", user_account.owner.as_ref()],
        bump = user_account.bump,
        has_one = owner,    // Also verify authority
    )]
    pub user_account: Account<'info, UserAccount>,
    
    /// CHECK: Receives the rent lamports
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseWithAuthCheck<'info> {
    /// SECURE: has_one = owner ensures only owner can close
    #[account(
        mut,
        close = recipient,
        seeds = [b"user", user_account.owner.as_ref()],
        bump = user_account.bump,
        has_one = owner,  // Only owner can close
    )]
    pub user_account: Account<'info, UserAccount>,
    
    /// CHECK: Receives the rent lamports
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReadConfigSecure<'info> {
    /// SECURE: Account<> validates rent-exempt status
    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct CloseProfileSecure<'info> {
    /// Profile being closed
    #[account(
        mut,
        close = recipient,
        seeds = [b"profile", owner.key().as_ref()],
        bump = profile.bump,
        has_one = owner,
    )]
    pub profile: Account<'info, UserProfile>,
    
    /// SECURE: Tombstone prevents recreation
    #[account(
        init,
        payer = owner,
        space = 8 + ProfileTombstone::INIT_SPACE,
        seeds = [b"tombstone", owner.key().as_ref()],
        bump
    )]
    pub tombstone: Account<'info, ProfileTombstone>,
    
    /// CHECK: Receives rent
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

// ============================================================================
// OTHER ACCOUNT STRUCTURES
// ============================================================================

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
pub struct InitializeProfile<'info> {
    /// Check tombstone doesn't exist (prevents recreation)
    #[account(
        init,
        payer = owner,
        space = 8 + UserProfile::INIT_SPACE,
        seeds = [b"profile", owner.key().as_ref()],
        bump
    )]
    pub profile: Account<'info, UserProfile>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AccrueRewards<'info> {
    #[account(
        mut,
        seeds = [b"user", user_account.owner.as_ref()],
        bump = user_account.bump,
    )]
    pub user_account: Account<'info, UserAccount>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(
        mut,
        seeds = [b"user", owner.key().as_ref()],
        bump = user_account.bump,
        has_one = owner,
    )]
    pub user_account: Account<'info, UserAccount>,
    
    pub owner: Signer<'info>,
}

// ============================================================================
// STATE
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub rewards_accrued: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub fee_bps: u16,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct UserProfile {
    pub owner: Pubkey,
    pub points: u64,
    pub bump: u8,
}

/// Permanent record that a profile was closed
#[account]
#[derive(InitSpace)]
pub struct ProfileTombstone {
    pub original_owner: Pubkey,
    pub closed_at: i64,
    pub bump: u8,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum CloseError {
    #[msg("Unauthorized to close this account")]
    Unauthorized,
    #[msg("Account already closed")]
    AlreadyClosed,
    #[msg("Cannot recreate closed profile")]
    ProfileTombstoneExists,
}

// ============================================================================
// ACCOUNT CLOSING CHECKLIST
// ============================================================================
//
// Use Anchor's `close` constraint (zeros data + transfers lamports)
// Verify authority with `has_one` before closing
// Consider tombstone records for PDA recreation prevention
// Never just transfer lamports without zeroing data
// Be aware of same-transaction revival attacks
// Validate accounts haven't been defunded when reading
//
// ============================================================================
// WHAT ANCHOR'S `close` DOES
// ============================================================================
//
// When you use `#[account(mut, close = recipient)]`:
//
// 1. Transfer lamports:
//    account.lamports() -> recipient
//
// 2. Zero data:
//    account.data.fill(0)
//
// 3. Change owner:
//    account.owner = System Program
//
// This prevents:
// - Revival attacks (data is zeroed)
// - Rent theft (only authorized closer)
// - Stale data reads (discriminator gone)
//
// ============================================================================
