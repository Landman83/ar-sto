// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title IEscrow
 * @dev Interface for the Escrow contract to avoid circular dependencies
 * @notice This is a consolidated interface that combines all methods
 */
interface IEscrow {
    // Basic escrow information
    function getTokenAllocation(address _investor) external view returns (uint256);
    function getInvestment(address _investor) external view returns (uint256);
    function isFinalized() external view returns (bool);
    function isSTOClosed() external view returns (bool);
    function isSoftCapReached() external view returns (bool);
    
    // Additional functionality from utils/IEscrow.sol
    function processWithdrawal(address _investor, uint256 _amount) external;
    function getTotalTokensSold() external view returns (uint256);
}