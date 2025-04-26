// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Events
 * @dev Library containing all events used in the STO system
 */
library Events {
    // ===== General Administrative Events =====
    event ContractInitialized(address indexed implementation, uint256 version);
    event ImplementationUpgraded(address indexed previousImplementation, address indexed newImplementation);
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);
    event OperatorAdded(address indexed operator, address indexed addedBy);
    event OperatorRemoved(address indexed operator, address indexed removedBy);
    event ContractPaused(address indexed operator);
    event ContractUnpaused(address indexed operator);
    event EmergencyShutdown(address indexed executor, string reason);
    
    // ===== STO Lifecycle Events =====
    // CappedSTO events - Maintaining original signatures
    event TokenPurchase(address indexed purchaser, address indexed beneficiary, uint256 value, uint256 amount);
    event SetAllowBeneficialInvestments(bool allowed);
    event STOFinalized(bool softCapReached);
    event InvestmentWithdrawn(address indexed investor, uint256 amount);
    event FinalizationRequired();
    event OrderExecuted(address indexed investor, uint256 investmentAmount, uint256 tokenAmount, uint256 nonce);
    event OrderCancelled(address indexed investor, uint256 nonce);
    
    // Extended STO Lifecycle Events
    event STOCreated(
        uint256 indexed offeringId, 
        address indexed securityToken, 
        address indexed creator, 
        uint256 startTime, 
        uint256 endTime
    );
    event STOConfigured(
        uint256 indexed offeringId,
        uint256 hardCap,
        uint256 softCap,
        uint256 rate,
        address investmentToken
    );
    event STOStarted(uint256 indexed offeringId, uint256 startTime);
    event STOPaused(uint256 indexed offeringId, address indexed operator);
    event STOResumed(uint256 indexed offeringId, address indexed operator);
    event STOCancelled(uint256 indexed offeringId, address indexed operator, string reason);
    event STOSettingsUpdated(uint256 indexed offeringId, string settingName);
    event InvestorAdded(uint256 indexed offeringId, address indexed investor);
    event InvestorRemoved(uint256 indexed offeringId, address indexed investor);
    
    // ===== Cap Events =====
    // Original events
    event SoftCapReached();
    event HardCapReached();
    
    // Extended cap events
    event CapUpdated(uint256 indexed offeringId, string capType, uint256 newValue);
    
    // ===== Escrow Events =====
    // Original events
    event FundsDeposited(address indexed investor, uint256 amount, uint256 tokenAllocation);
    event FundsReleased(address indexed wallet, uint256 amount);
    event EscrowFinalized(bool softCapReached);
    event STOClosed(bool hardCapReached, bool endTimeReached);
    
    // Extended escrow events
    event EscrowCreated(uint256 indexed offeringId, address indexed escrowContract);
    
    // ===== Refund Events =====
    // Original events
    event RefundsInitialized();
    event RefundClaimed(address indexed investor, uint256 amount);
    event RefundProcessed(address indexed investor, uint256 amount);
    event WithdrawalProcessed(address indexed investor, uint256 amount);
    
    // Extended refund events
    event RefundPeriodChanged(uint256 indexed offeringId, uint256 newPeriodDuration);
    
    // ===== Minting Events =====
    // Original events
    event MintingInitialized();
    event TokensDelivered(address indexed investor, uint256 amount);
    event MintingDelegated(address indexed tokenOwner, address indexed investor, uint256 amount);
    
    // Extended minting events
    event MintingBatchProcessed(uint256 numInvestors, uint256 totalTokens);
    event TokenDistributionComplete(uint256 indexed offeringId);
    
    // ===== Pricing Events =====
    // Original events - maintain signature
    event RateChanged(uint256 newRate);
    
    // Extended pricing events
    event MinInvestmentChanged(uint256 oldMinimum, uint256 newMinimum);
    event MaxInvestmentChanged(uint256 oldMaximum, uint256 newMaximum);
    event TierAdded(uint256 threshold, uint256 rate);
    event TierRemoved(uint256 threshold);
    event PricingStrategyChanged(address indexed oldStrategy, address indexed newStrategy);
    event AuctionPriceUpdated(uint256 newPrice);
    
    // ===== Fee Events =====
    // Original events - maintain signature
    event FeeRateChanged(uint256 newFeeRate);
    event FeeWalletChanged(address indexed newFeeWallet);
    event FeeOwnershipTransferred(address indexed newOwner);
    event FeeCollected(address indexed feeWallet, uint256 feeAmount);
    
    // Extended fee events
    event FeeDistributed(address[] recipients, uint256[] amounts);
    
    // ===== Compliance & Verification Events =====
    event AttributeRegistrySet(address indexed registry);
    event InvestorVerified(address indexed investor, bool status);
    event InvestorVerificationRequested(address indexed investor, bytes32 dataHash);
    event ComplianceCheckPerformed(address indexed investor, bool passed);
    event TransferRestrictionChanged(string restrictionType, bool active);
    event CountryRestrictionChanged(string countryCode, bool restricted);
    event BatchVerificationProcessed(uint256 processedCount, uint256 successCount);
    
    // ===== Factory Events =====
    event STOFactoryInitialized(address indexed owner);
    event STODeployed(
        address indexed stoAddress, 
        address indexed securityToken, 
        address indexed owner,
        uint256 offeringId
    );
    event ModuleDeployed(address indexed moduleAddress, string moduleType);
    event ImplementationRegistered(string contractType, address indexed implementation, string version);
    event ImplementationRemoved(string contractType, address indexed implementation);
    
    // ===== Wallet Events =====
    event WalletRegistered(address indexed walletAddress, string walletType);
    event WalletRemoved(address indexed walletAddress);
    event FundsSwept(address indexed token, address indexed destination, uint256 amount);
    
    // ===== Referral Events =====
    event ReferralRecorded(address indexed referrer, address indexed investor);
    event ReferralRewardPaid(address indexed referrer, uint256 amount);
    event ReferralProgramUpdated(uint256 newRewardRate);
}