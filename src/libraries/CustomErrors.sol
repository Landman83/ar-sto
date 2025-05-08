// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @dev Library containing all custom errors used in the STO system

// ===== General Errors =====
error ZeroAddress(string param);
error Unauthorized(address caller, string role);
error AlreadyInitialized(address contractAddress);
error NotInitialized(address contractAddress);
error InvalidParameter(string param, string reason);
error InvalidOperation(string operation, string reason);
error InvalidState(string expectedState, string actualState);
error NotOperator(address caller);
error NotOwner(address caller);
error NotAdmin(address caller);
error Paused();
error NotPaused();

// ===== STO Errors =====
error STONotStarted(uint256 startTime, uint256 currentTime);
error STOEnded(uint256 endTime, uint256 currentTime);
error STOClosed();
error STONotClosed();
error STOAlreadyFinalized();
error STONotFinalized();
error InvalidDates(uint256 startDate, uint256 endDate);
error CannotCancel(string reason);
error InvestorLimitReached(uint256 limit);
error STONotActive();
error STOAlreadyActive();

// ===== Cap Errors =====
error HardCapReached(uint256 hardCap);
error SoftCapNotReached(uint256 softCap, uint256 amountRaised);
error SoftCapAlreadyReached(uint256 softCap);
error InvalidCap(uint256 hardCap, uint256 softCap);
error ZeroCap();

// ===== Investment Errors =====
error ZeroInvestment();
error BelowMinInvestment(uint256 minAmount, uint256 providedAmount);
error AboveMaxInvestment(uint256 maxAmount, uint256 providedAmount);
error InvestmentFailed(string reason);
error TransferFailed(address token, address from, address to, uint256 amount);
error ApprovalFailed(address token, address spender, uint256 amount);
error AlreadyInvestor(address investor);
error NoTokensAllocated(address investor);
error InvestmentPeriodClosed();

// ===== Pricing Errors =====
error ZeroRate();
error InvalidPrice(uint256 expectedPrice, uint256 actualPrice);
error InsufficientTokensAvailable(uint256 requested, uint256 available);
error PriceChanged(uint256 oldPrice, uint256 newPrice);
error TieredPriceError(string reason);

// ===== Escrow Errors =====
error EscrowNotFinalized();
error EscrowAlreadyFinalized();
error EscrowReleaseFailed(string reason);
error InsufficientEscrowBalance(uint256 requested, uint256 available);
error EscrowUnauthorized(address caller);

// ===== Refund Errors =====
error AlreadyClaimedRefund(address investor);
error NoRefundAvailable(address investor);
error RefundPeriodEnded(uint256 endTime);
error RefundFailed(address token, address investor, uint256 amount);
error RefundCalculationError(string reason);
error WithdrawalLimitExceeded(uint256 limit, uint256 requested);

// ===== Minting Errors =====
error AlreadyClaimedTokens(address investor);
error NoTokensToClaim(address investor);
error MintingFailed(address token, address investor, uint256 amount);
error ClaimPeriodEnded(uint256 endTime);
error TokenTransferFailed(address token, address to, uint256 amount);

// ===== Compliance Errors =====
error NotVerified(address investor);
error VerificationRequired(address investor);
error AccreditationRequired(address investor);
error VerificationExpired(address investor, uint256 expiryTime);
error RestrictedInvestor(address investor, string reason);
error RestrictedCountry(string country);
error ComplianceCheckFailed(address investor, string reason);
error RestrictedSale(address from, address to, string reason);

// ===== Signature & Order Errors =====
error InvalidSignature(address recovered, address expected);
error InvalidNonce(address investor, uint256 expected, uint256 provided);
error OrderExpired(uint256 expiry, uint256 currentTime);
error OrderAlreadyProcessed(bytes32 orderHash);
error InvalidOrderParameters(string reason);
error SelfTransferNotAllowed(address sender, address beneficiary);

// ===== Factory & Proxy Errors =====
error InvalidImplementation(address implementation);
error UpgradeFailed(address implementation, string reason);
error IncompatibleImplementation(address implementation);
error InitializationFailed(string reason);
error DeploymentFailed(string reason);

// ===== Fee Errors =====
error FeeCalculationError(string reason);
error FeeTransferFailed(address token, address recipient, uint256 amount);
error ExcessiveFee(uint256 fee, uint256 maxAllowed);
error FeeAlreadyPaid(bytes32 transactionId);

// ===== Referral Errors =====
error SelfReferral(address user);
error InvalidReferralCode(string code);
error ReferralAlreadyUsed(string code, address user);
error ReferralRewardFailed(address recipient, uint256 amount);