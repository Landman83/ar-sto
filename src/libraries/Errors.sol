// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Errors
 * @dev Library containing all error messages used in the STO system
 */
library Errors {
    // ===== General Errors =====
    string constant ZERO_ADDRESS = "Zero address is not permitted";
    string constant UNAUTHORIZED = "Caller is not authorized";
    string constant ALREADY_INITIALIZED = "Already initialized";
    string constant NOT_INITIALIZED = "Contract not initialized";
    string constant INVALID_PARAMETER = "Invalid parameter provided";
    string constant INVALID_OPERATION = "Invalid operation";
    string constant INVALID_STATE = "Invalid state for this operation";
    string constant NOT_OPERATOR = "Caller is not the operator";
    string constant NOT_OWNER = "Caller is not the owner";
    string constant NOT_ADMIN = "Caller is not the admin";
    string constant PAUSED = "Contract is paused";
    string constant NOT_PAUSED = "Contract is not paused";
    
    // ===== STO Errors =====
    string constant NOT_STARTED = "STO not started";
    string constant ENDED = "STO has ended";
    string constant CLOSED = "STO is closed";
    string constant NOT_CLOSED = "STO is not closed";
    string constant ALREADY_FINALIZED = "STO is already finalized";
    string constant NOT_FINALIZED = "STO is not finalized";
    string constant INVALID_DATES = "Start date must be before end date";
    string constant CANNOT_CANCEL = "STO cannot be cancelled at this stage";
    string constant INVESTOR_LIMIT_REACHED = "Maximum investor limit reached";
    string constant STO_NOT_ACTIVE = "STO is not in active state";
    string constant STO_ALREADY_ACTIVE = "STO is already active";
    
    // ===== Cap Errors =====
    string constant HARD_CAP_REACHED = "Hard cap reached";
    string constant SOFT_CAP_NOT_REACHED = "Soft cap not reached";
    string constant SOFT_CAP_ALREADY_REACHED = "Soft cap already reached";
    string constant INVALID_CAP = "Hard cap must be greater than soft cap";
    string constant ZERO_CAP = "Cap cannot be zero";
    
    // ===== Investment Errors =====
    string constant ZERO_INVESTMENT = "Investment amount must be greater than 0";
    string constant BELOW_MIN_INVESTMENT = "Investment amount below minimum";
    string constant ABOVE_MAX_INVESTMENT = "Investment amount above maximum";
    string constant INVESTMENT_FAILED = "Investment transaction failed";
    string constant TRANSFER_FAILED = "Token transfer failed";
    string constant APPROVAL_FAILED = "Token approval failed";
    string constant ALREADY_INVESTOR = "Already an investor";
    string constant NO_TOKENS_ALLOCATED = "No tokens allocated to this address";
    string constant INVESTMENT_PERIOD_CLOSED = "Investment period closed";
    
    // ===== Pricing Errors =====
    string constant ZERO_RATE = "Rate must be greater than 0";
    string constant INVALID_PRICE = "Invalid price calculation";
    string constant INSUFFICIENT_TOKENS = "Insufficient tokens available at this price";
    string constant PRICE_CHANGED = "Price has changed, please retry";
    string constant TIERED_PRICE_ERROR = "Tiered pricing configuration error";
    
    // ===== Escrow Errors =====
    string constant ESCROW_NOT_FINALIZED = "Escrow not finalized";
    string constant ESCROW_ALREADY_FINALIZED = "Escrow already finalized";
    string constant ESCROW_RELEASE_FAILED = "Escrow funds release failed";
    string constant INSUFFICIENT_ESCROW_BALANCE = "Insufficient balance in escrow";
    string constant ESCROW_UNAUTHORIZED = "Not authorized to manage escrow";
    
    // ===== Refund Errors =====
    string constant ALREADY_CLAIMED_REFUND = "Already claimed refund";
    string constant NO_REFUND_AVAILABLE = "No refund available";
    string constant REFUND_PERIOD_ENDED = "Refund period has ended";
    string constant REFUND_FAILED = "Refund transfer failed";
    string constant REFUND_CALCULATION_ERROR = "Error calculating refund amount";
    string constant WITHDRAWAL_LIMIT_EXCEEDED = "Withdrawal limit exceeded";
    
    // ===== Minting Errors =====
    string constant ALREADY_CLAIMED_TOKENS = "Already claimed tokens";
    string constant NO_TOKENS_TO_CLAIM = "No tokens to claim";
    string constant MINTING_FAILED = "Token minting failed";
    string constant CLAIM_PERIOD_ENDED = "Claim period has ended";
    string constant TOKEN_TRANSFER_FAILED = "Token transfer failed";
    
    // ===== Compliance Errors =====
    string constant NOT_VERIFIED = "Investor is not verified";
    string constant VERIFICATION_REQUIRED = "KYC verification required";
    string constant ACCREDITATION_REQUIRED = "Accredited investor status required";
    string constant VERIFICATION_EXPIRED = "Verification has expired";
    string constant RESTRICTED_INVESTOR = "Investor is restricted from this offering";
    string constant RESTRICTED_COUNTRY = "Country is restricted from this offering";
    string constant COMPLIANCE_CHECK_FAILED = "Compliance check failed";
    string constant RESTRICTED_SALE = "Token transfer restricted by compliance rules";
    
    // ===== Signature & Order Errors =====
    string constant INVALID_SIGNATURE = "Invalid signature";
    string constant INVALID_NONCE = "Invalid nonce";
    string constant ORDER_EXPIRED = "Order has expired";
    string constant ORDER_ALREADY_PROCESSED = "Order already processed";
    string constant INVALID_ORDER_PARAMETERS = "Invalid order parameters";
    string constant SELF_TRANSFER_NOT_ALLOWED = "Self transfer not allowed";
    
    // ===== Factory & Proxy Errors =====
    string constant INVALID_IMPLEMENTATION = "Invalid implementation address";
    string constant UPGRADE_FAILED = "Contract upgrade failed";
    string constant INCOMPATIBLE_IMPLEMENTATION = "Incompatible implementation";
    string constant INITIALIZATION_FAILED = "Initialization failed";
    string constant DEPLOYMENT_FAILED = "Contract deployment failed";
    
    // ===== Fee Errors =====
    string constant FEE_CALCULATION_ERROR = "Error calculating fee";
    string constant FEE_TRANSFER_FAILED = "Fee transfer failed";
    string constant EXCESSIVE_FEE = "Fee exceeds maximum allowed";
    string constant FEE_ALREADY_PAID = "Fee already paid for this transaction";
    
    // ===== Referral Errors =====
    string constant SELF_REFERRAL = "Self-referral not allowed";
    string constant INVALID_REFERRAL_CODE = "Invalid referral code";
    string constant REFERRAL_ALREADY_USED = "Referral already used";
    string constant REFERRAL_REWARD_FAILED = "Referral reward distribution failed";
}