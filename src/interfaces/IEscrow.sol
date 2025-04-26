// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;  
/**
@title IEscrow
@dev Interface for the Escrow contract to avoid circular dependencies
*/
interface IEscrow {
      function getTokenAllocation(address _investor) external view returns (uint256);
      function getInvestment(address _investor) external view returns (uint256);
      function isFinalized() external view returns (bool);
      function isSTOClosed() external view returns (bool);
      function isSoftCapReached() external view returns (bool);
  }