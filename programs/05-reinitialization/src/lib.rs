//! # Reinitialization Attack Vulnerability
//! 
//! ## Overview
//! Reinitialization attacks occur when an account that has already been
//! initialized can be initialized again, allowing attackers to:
//! - Reset state to favorable values
//! - Change ownership of accounts
//! - Drain funds by manipulating counters/balances
//! 
//! ## The Attack Pattern
//! 1. Account is properly initialized with correct state
//! 2. Attacker calls initialize again (if not prevented)
//! 3. State is reset - attacker becomes new owner, balances reset, etc.
//! 4. Attacker exploits the reset state
//! 
//! ## Why This Happens
//! Programs often create separate `initialize` instructions without
//! checking if the account is already initialized.

use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnW");

#[program]
pub mod reinitialization {
    use super::*;

    // ============================================================================
    // VULNERABILITY 1: NO INITIALIZATION CHECK
    // ============================================================================

    /// VULNERABLE: Account can be initialized multiple times.
    /// 
    /// ## What's Wrong?
    /// This instruction doesn't check if the account is already initialized.
    /// An attacker can call it again to:
    /// - Reset the balance to 0 (steal existing deposits)
    /// - Change the authority to themselves
    /// - Reset counters that track withdrawals
    /// 
    /// ## Attack Scenario:
    /// 1. Alice creates vault with 100 SOL, authority = Alice
    /// 2. Attacker calls initialize_vulnerable on Alice's vault
    /// 3. Vault now has: balance = 0, authority = Attacker
    /// 4. Alice's 100 SOL is now stuck (or attacker withdraws it)
    pub fn initialize_vulnerable(
        ctx: Context<InitializeVulnerable>,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // DANGER: We just overwrite whatever was there!
        // No check if vault was already initialized
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.total_deposits = 0;
        vault.total_withdrawals = 0;
        vault.is_initialized = true;
        
        msg!("VULNERABLE: Initialized vault (but maybe re-initialized!)");
        Ok(())
    }

    /// SECURE (Manual Check): Verifies account is not already initialized.
    /// 
    /// ## What's Fixed?
    /// We check the `is_initialized` flag before allowing initialization.
    /// This is the manual approach - works but requires discipline.
    pub fn initialize_secure_manual(
        ctx: Context<InitializeSecureManual>,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // SECURE: Check initialization flag
        require!(!vault.is_initialized, ReinitError::AlreadyInitialized);
        
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.total_deposits = 0;
        vault.total_withdrawals = 0;
        vault.is_initialized = true;
        
        msg!("SECURE (manual): Initialized vault with flag check");
        Ok(())
    }

    /// SECURE (Anchor): Uses Anchor's `init` constraint.
    /// 
    /// ## What's Fixed?
    /// The `init` constraint:
    /// 1. Creates the account (fails if already exists at that address)
    /// 2. Sets the owner to the program
    /// 3. Sets the discriminator (8-byte type identifier)
    /// 4. Cannot be called twice on same account
    /// 
    /// This is the recommended approach - Anchor handles everything.
    pub fn initialize_secure_anchor(
        ctx: Context<InitializeSecureAnchor>,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // SECURE: Anchor's `init` already ensures this is a new account
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.total_deposits = 0;
        vault.total_withdrawals = 0;
        // Note: is_initialized not needed with Anchor's init
        vault.bump = ctx.bumps.vault;
        
        msg!("SECURE (Anchor): Initialized vault with init constraint");
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 2: DISCRIMINATOR MANIPULATION
    // ============================================================================

    /// VULNERABLE: Uses raw account without discriminator check.
    /// 
    /// ## What's Wrong?
    /// Without discriminator validation, attacker could potentially:
    /// - Create account with data that looks like "uninitialized"
    /// - Bypass is_initialized checks by manipulating raw bytes
    /// 
    /// ## The Discriminator
    /// Anchor adds an 8-byte discriminator (hash of account type name)
    /// at the start of every account. This prevents:
    /// - Using wrong account type
    /// - Treating uninitialized data as initialized
    /// - Type confusion attacks
    pub fn process_vault_vulnerable(
        ctx: Context<ProcessVaultVulnerable>,
    ) -> Result<()> {
        // DANGER: Reading raw account data without proper validation
        let data = ctx.accounts.vault_info.try_borrow_data()?;
        
        // Attacker could craft data to pass this check
        let is_initialized = data[0] == 1;
        
        if !is_initialized {
            msg!("VULNERABLE: Processing 'uninitialized' vault");
            // Would allow initialization...
        }
        
        Ok(())
    }

    /// SECURE: Account<> type handles discriminator automatically.
    pub fn process_vault_secure(
        ctx: Context<ProcessVaultSecure>,
    ) -> Result<()> {
        // SECURE: Anchor validated discriminator during deserialization
        let vault = &ctx.accounts.vault;
        
        msg!("SECURE: Processing vault owned by {}", vault.authority);
        Ok(())
    }

    // ============================================================================
    // VULNERABILITY 3: CONFIG REINIT
    // ============================================================================

    /// VULNERABLE: Global config can be reinitialized.
    /// 
    /// ## What's Wrong?
    /// Protocol config (fees, admin, limits) can be reset.
    /// Attacker can:
    /// - Set themselves as admin
    /// - Set fees to 0 or 100%
    /// - Change protocol parameters
    /// 
    /// ## Attack Scenario:
    /// 1. Protocol deployed with admin = deployer, fee = 1%
    /// 2. Attacker calls reinitialize_config
    /// 3. Config now: admin = attacker, fee = 0%
    /// 4. Attacker has full control of protocol
    pub fn initialize_config_vulnerable(
        ctx: Context<InitializeConfigVulnerable>,
        fee_bps: u16,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // DANGER: Overwrites existing config!
        config.admin = ctx.accounts.admin.key();
        config.fee_bps = fee_bps;
        config.is_initialized = true;
        
        msg!("VULNERABLE: Config (re)initialized with fee {}bps", fee_bps);
        Ok(())
    }

    /// SECURE: Config can only be initialized once.
    pub fn initialize_config_secure(
        ctx: Context<InitializeConfigSecure>,
        fee_bps: u16,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // SECURE: Anchor's init ensures this PDA doesn't exist yet
        config.admin = ctx.accounts.admin.key();
        config.fee_bps = fee_bps;
        config.bump = ctx.bumps.config;
        
        msg!("SECURE: Config initialized with fee {}bps", fee_bps);
        Ok(())
    }

    // ============================================================================
    // HELPER INSTRUCTIONS
    // ============================================================================

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance.checked_add(amount).unwrap();
        vault.total_deposits = vault.total_deposits.checked_add(amount).unwrap();
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(vault.authority == ctx.accounts.authority.key(), ReinitError::Unauthorized);
        vault.balance = vault.balance.checked_sub(amount).unwrap();
        vault.total_withdrawals = vault.total_withdrawals.checked_add(amount).unwrap();
        Ok(())
    }
}

// ============================================================================
// VULNERABLE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct InitializeVulnerable<'info> {
    /// VULNERABLE: `mut` without `init` allows reinitialization!
    /// 
    /// The account already exists and we can just overwrite it.
    /// Should use `init` constraint for first-time creation.
    #[account(mut)]
    pub vault: Account<'info, VaultVulnerable>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeSecureManual<'info> {
    /// Still vulnerable to edge cases - manual check in instruction
    #[account(mut)]
    pub vault: Account<'info, VaultVulnerable>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ProcessVaultVulnerable<'info> {
    /// VULNERABLE: Raw account access bypasses discriminator
    /// 
    /// CHECK: Intentionally insecure for demonstration
    pub vault_info: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct InitializeConfigVulnerable<'info> {
    /// VULNERABLE: Can be called multiple times
    #[account(mut)]
    pub config: Account<'info, ConfigVulnerable>,
    
    pub admin: Signer<'info>,
}

// ============================================================================
// SECURE ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct InitializeSecureAnchor<'info> {
    /// SECURE: `init` constraint ensures:
    /// 
    /// 1. Account doesn't exist yet (creates it)
    /// 2. Program becomes owner
    /// 3. Discriminator is set
    /// 4. Cannot be called twice (address already taken)
    #[account(
        init,
        payer = authority,
        space = 8 + VaultSecure::INIT_SPACE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, VaultSecure>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ProcessVaultSecure<'info> {
    /// SECURE: Account<> validates discriminator
    #[account(
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, VaultSecure>,
}

#[derive(Accounts)]
pub struct InitializeConfigSecure<'info> {
    /// SECURE: PDA + init = cannot reinitialize
    #[account(
        init,
        payer = admin,
        space = 8 + ConfigSecure::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, ConfigSecure>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, VaultSecure>,
    
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"vault", vault.authority.as_ref()],
        bump = vault.bump,
    )]
    pub vault: Account<'info, VaultSecure>,
    
    pub authority: Signer<'info>,
}

// ============================================================================
// STATE - VULNERABLE VERSIONS
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct VaultVulnerable {
    pub authority: Pubkey,
    pub balance: u64,
    pub total_deposits: u64,
    pub total_withdrawals: u64,
    /// Manual initialization flag - can be bypassed!
    pub is_initialized: bool,
}

#[account]
#[derive(InitSpace)]
pub struct ConfigVulnerable {
    pub admin: Pubkey,
    pub fee_bps: u16,
    pub is_initialized: bool,
}

// ============================================================================
// STATE - SECURE VERSIONS
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct VaultSecure {
    pub authority: Pubkey,
    pub balance: u64,
    pub total_deposits: u64,
    pub total_withdrawals: u64,
    /// PDA bump - no need for is_initialized flag
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ConfigSecure {
    pub admin: Pubkey,
    pub fee_bps: u16,
    pub bump: u8,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum ReinitError {
    #[msg("Account is already initialized")]
    AlreadyInitialized,
    #[msg("Unauthorized")]
    Unauthorized,
}

// ============================================================================
// WHY ANCHOR'S `init` IS THE BEST SOLUTION
// ============================================================================
//
// 1. ATOMIC: Account creation and initialization happen together
//    - No window where account exists but isn't initialized
//    - No race conditions
//
// 2. ADDRESS UNIQUENESS: PDA seeds ensure unique addresses
//    - Same seeds always produce same address
//    - Can't create duplicate accounts
//
// 3. DISCRIMINATOR: 8-byte type identifier
//    - Prevents type confusion attacks
//    - Allows safe deserialization
//
// 4. OWNER CHECK: Program automatically becomes owner
//    - Can't use accounts owned by other programs
//    - Clear ownership model
//
// ============================================================================
// COMPARISON: MANUAL vs ANCHOR INIT
// ============================================================================
//
// | Aspect            | Manual Flag          | Anchor `init`            |
// |-------------------|----------------------|--------------------------|
// | Implementation    | Check in instruction | Constraint in accounts   |
// | Race Condition    | Possible             | Impossible               |
// | Discriminator     | None                 | Automatic                |
// | Account Creation  | Separate step        | Integrated               |
// | Can Be Bypassed   | Yes (raw access)     | No                       |
// | Recommended       | No                   | Yes                      |
//
// ============================================================================
