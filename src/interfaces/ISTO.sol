// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../libraries/Order.sol";

/**
 * @title Interface for the Security Token Offering (STO) contract
 * @notice Comprehensive interface defining core STO functionality
 */
interface ISTO {
    /**
     * @notice Issue tokens to a specific investor
     * @param _investor Address of the investor
     * @param _amount Amount of tokens to issue
     */
    function issueTokens(address _investor, uint256 _amount) external;
    
    /**
     * @notice Purchase tokens with ERC20 token
     * @param _beneficiary Address performing the token purchase
     * @param _investedAmount Amount of ERC20 tokens to invest
     */
    function buyTokens(address _beneficiary, uint256 _investedAmount) external;
    
    /**
     * @notice Execute a signed order from an investor
     * @param order The order details signed by the investor
     * @param signature The EIP-712 signature from the investor
     */
    function executeSignedOrder(
        Order.OrderInfo calldata order,
        bytes calldata signature
    ) external;
    
    /**
     * @notice Finalize the offering
     * @dev Can only be called after the offering end time or when hard cap is reached
     */
    function finalize() external;
    
    /**
     * @notice Allow investors to withdraw some or all of their investment before offering closes
     * @param _amount Amount to withdraw
     */
    function withdrawInvestment(uint256 _amount) external;
    
    /**
     * @notice Claim refund if soft cap was not reached
     */
    function claimRefund() external;
    
    /**
     * @notice Get the current nonce for an investor (for signed orders)
     * @param investor The investor address
     * @return The current nonce
     */
    function getNonce(address investor) external view returns (uint256);
    
    /**
     * @notice Return the total number of tokens sold
     * @return The total number of tokens sold
     */
    function getTokensSold() external view returns (uint256);
    
    /**
     * @notice Get all investors
     * @return Array of investor addresses
     */
    function getAllInvestors() external view returns (address[] memory);
    
    /**
     * @notice Check if an investor has received their tokens
     * @param _investor Address of the investor
     * @return Whether the investor has received tokens
     */
    function hasReceivedTokens(address _investor) external view returns (bool);
    
    /**
     * @notice Check if an investor has claimed their refund
     * @param _investor Address of the investor
     * @return Whether the investor has claimed a refund
     */
    function hasClaimedRefund(address _investor) external view returns (bool);
}