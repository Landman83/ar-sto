// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../libraries/Order.sol";

/**
 * @title Interface for the Investment Manager
 * @notice Defines functionality for managing investments in STO
 */
interface IInvestmentManager {
    /**
     * @notice Purchase tokens with ERC20 token
     * @param _buyer Address performing the token purchase (sender)
     * @param _beneficiary Address to receive the tokens
     * @param _investedAmount Amount of ERC20 tokens to invest
     * @return tokens Amount of tokens purchased
     * @return refund Amount refunded if any
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
     */
    function setTimeParameters(uint256 _startTime, uint256 _endTime) external;
    
    /**
     * @notice Change whether beneficial investments are allowed
     * @param _allowBeneficialInvestments Flag to allow/disallow beneficial investments
     */
    function setAllowBeneficialInvestments(bool _allowBeneficialInvestments) external;
    
    /**
     * @notice Set the signatures contract
     * @param _signaturesContract Address of the new signatures contract
     */
    function setSignaturesContract(address _signaturesContract) external;
    
    /**
     * @notice Set the fund raise type (for tracking purposes)
     * @param fundRaiseType The fund raise type enum value
     */
    function setFundRaiseType(uint8 fundRaiseType) external;
    
    /**
     * @notice Get the current nonce for an investor
     * @param investor The investor address
     * @return The current nonce
     */
    function getNonce(address investor) external view returns (uint256);
    
    /**
     * @notice Get all investors
     * @return Array of investor addresses
     */
    function getAllInvestors() external view returns (address[] memory);
}