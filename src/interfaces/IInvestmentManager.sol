// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../libraries/Order.sol";

/**
 * @title IInvestmentManager - Interface for the Investment Manager
 * @notice Defines the contract responsible for managing all investment operations in an STO
 * @dev This interface explicitly defines all methods that can be called by other contracts,
 *      making dependencies between components clear and formal. The InvestmentManager serves
 *      as the source of truth for investor data, investment amounts, and signature validation.
 *
 * Dependencies:
 * - Requires initialized Escrow contract to deposit funds
 * - Requires PricingLogic contract to calculate token amounts
 * - Requires an optional Signatures contract for order validation
 * - Requires VerificationManager for compliance checks
 * - Requires Compliance contract for regulatory validation
 * - Requires STOConfig for configuration parameters
 */
interface IInvestmentManager {
    /**
     * @notice Purchase tokens with ERC20 token
     * @param _buyer Address performing the token purchase (sender)
     * @param _beneficiary Address to receive the tokens
     * @param _investedAmount Amount of ERC20 tokens to invest
     * @return tokens Amount of tokens purchased
     * @return refund Amount refunded if any
     * @dev This is the main investment function that:
     *      1. Validates the investor and parameters
     *      2. Calculates token amounts using the pricing logic
     *      3. Deposits funds into escrow
     *      4. Tracks investor data
     *      5. Returns any refund amount (if hardcap would be exceeded)
     *      The caller is responsible for sending any refund back to the buyer
     */
    function buyTokens(
        address _buyer, 
        address _beneficiary, 
        uint256 _investedAmount
    ) external returns (uint256 tokens, uint256 refund);
    
    /**
     * @notice Execute a signed order from an investor
     * @param _sender Address executing the order (usually an operator)
     * @param order The order details signed by the investor
     * @param signature The EIP-712 signature from the investor
     * @return tokens Amount of tokens purchased
     * @return refund Amount refunded if any
     * @dev Validates signature using the signatures contract, ensuring:
     *      1. The signature is valid for this exact order
     *      2. The correct nonce is used (preventing replay attacks)
     *      3. All investment parameters are valid
     *      The caller is responsible for sending any refund back to the investor
     */
    function executeSignedOrder(
        address _sender,
        Order.OrderInfo calldata order,
        bytes calldata signature
    ) external returns (uint256 tokens, uint256 refund);
    
    /**
     * @notice Set the time parameters for the offering
     * @param _startTime The start time of the offering
     * @param _endTime The end time of the offering
     * @dev Only callable by the STO contract
     *      Sets the time window when investments are accepted
     *      Investments before _startTime or after _endTime will be rejected
     *      Requires _startTime < _endTime
     */
    function setTimeParameters(uint256 _startTime, uint256 _endTime) external;
    
    /**
     * @notice Change whether beneficial investments are allowed
     * @param _allowBeneficialInvestments Flag to allow/disallow beneficial investments
     * @dev Only callable by the STO contract
     *      When true, investors can purchase tokens on behalf of others
     *      When false, beneficiary must be the same as the buyer
     *      The investment manager is the authoritative source for this setting
     */
    function setAllowBeneficialInvestments(bool _allowBeneficialInvestments) external;
    
    /**
     * @notice Get whether beneficial investments are currently allowed
     * @return Current setting for allowing beneficial investments
     * @dev This is the single source of truth for this configuration
     *      The main STO contract should defer to this value
     */
    function allowBeneficialInvestments() external view returns (bool);
    
    /**
     * @notice Set the signatures contract for validating orders
     * @param _signaturesContract Address of the new signatures contract
     * @dev Only callable by the STO contract
     *      The signatures contract must implement EIP-712 verification
     *      This is used for all signed orders to verify authenticity
     */
    function setSignaturesContract(address _signaturesContract) external;
    
    /**
     * @notice Set the fund raise type (for tracking purposes)
     * @param fundRaiseType The fund raise type enum value
     * @dev Only callable by the STO contract
     *      Determines which token is being used for investment
     *      Currently supports ERC20 tokens identified by the enum value
     */
    function setFundRaiseType(uint8 fundRaiseType) external;
    
    /**
     * @notice Get the current nonce for an investor
     * @param investor The investor address
     * @return The current nonce
     * @dev Used for creating and validating signed orders
     *      Each new order from an investor must use a nonce higher than the previous one
     *      This is the authoritative source for nonce tracking
     */
    function getNonce(address investor) external view returns (uint256);
    
    /**
     * @notice Increment the nonce for an investor
     * @param investor Address of the investor
     * @return The new nonce value
     * @dev Only callable by the STO contract
     *      Used to invalidate previously signed orders
     */
    function incrementNonce(address investor) external returns (uint256);
    
    /**
     * @notice Get all investors who have participated in the offering
     * @return Array of all investor addresses
     * @dev This is the authoritative source for investor tracking
     *      Used during finalization to mint tokens or process refunds
     *      May return a large array for offerings with many investors
     */
    function getAllInvestors() external view returns (address[] memory);
    
    /**
     * @notice Check if an address is an investor
     * @param _investor The address to check
     * @return Whether the address is an investor
     * @dev This is the authoritative source for checking investor status
     */
    function isInvestor(address _investor) external view returns (bool);
    
    /**
     * @notice Add a new investor to the tracked list
     * @param _investor Address of the investor to add
     * @return Whether the investor was newly added
     * @dev Only callable by the STO contract
     *      Returns false if investor was already added
     */
    function addInvestor(address _investor) external returns (bool);
    
    /**
     * @notice Get the address of the signatures contract
     * @return The address of the signatures contract
     * @dev Returns the contract used for signature verification
     */
    function signaturesContract() external view returns (address);
    
    /**
     * @notice Set the STOConfig contract 
     * @param _stoConfig Address of the STOConfig contract
     * @dev Only callable by the STO contract
     *      The STOConfig contract is the authoritative source for configuration parameters
     *      Used for all time-based validation, cap management, and fund tracking
     */
    function setSTOConfig(address _stoConfig) external;
}