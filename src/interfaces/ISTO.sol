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
    function getTotalTokensSold() external view returns (uint256);
    
    /**
     * @notice Get access to the investment manager
     * @return The investment manager contract
     */
    function getInvestmentManager() external view returns (address);
    
    /**
     * @notice Get access to the finalization manager
     * @return The finalization manager contract 
     */
    function getFinalizationManager() external view returns (address);
    
    /**
     * @notice Get access to the verification manager
     * @return The verification manager contract
     */
    function getVerificationManager() external view returns (address);
    
    /**
     * @notice Get the signatures contract used for EIP-712 signature verification
     * @return The signatures contract address
     */
    function signaturesContract() external view returns (address);
}