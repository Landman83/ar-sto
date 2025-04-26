// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Consolidated storage contract for all STO types
 * @dev This contract contains all storage variables used by STO implementations,
 * combining both base and specific storage patterns for better maintainability.
 * Layout follows a logical grouping pattern to improve readability and ensure
 * upgrade safety through proper storage slot management.
 */
contract STOStorage {
    // ============== Offering Time Configuration ==============
    
    /// @notice The start time of the offering in Unix timestamp format
    /// @dev Once set, this value should remain immutable for the offering
    uint256 public startTime;
    
    /// @notice The end time of the offering in Unix timestamp format
    /// @dev May be extended in certain scenarios by authorized roles
    uint256 public endTime;
    
    // ============== Fundraising Configuration ==============
    
    /// @notice Enum for supported investment token types
    /// @dev Values correspond to array indexes in mappings
    enum FundRaiseType { ETH, POLY, DAI, USDT, USDC, ERC20 }
    
    /// @notice Whether STOs of a specific fund raise type are allowed
    /// @dev Maps FundRaiseType enum values to boolean permission status
    mapping(uint8 => bool) public fundRaiseTypes;
    
    /// @notice Amount of funds raised per fund raise type
    /// @dev Maps FundRaiseType enum values to total raised amount (in token's smallest unit)
    mapping(uint8 => uint256) public fundsRaised;
    
    /// @notice Total number of tokens sold across all fundraise types
    /// @dev Updated during token purchases, represents total tokens distributed
    uint256 private tokensSold;
    
    // ============== CappedSTO Configuration ==============
    
    /// @notice The rate of token per investment token (multiplied by 10^18)
    /// @dev Acts as a conversion rate from investment token to security token
    uint256 public rate;
    
    /// @notice Hard cap for backward compatibility
    /// @dev Maximum number of tokens that can be sold in this offering
    uint256 public cap;
    
    /// @notice Address where investment token funds are collected
    /// @dev Primary destination for successful fundraising
    address payable public wallet;
    
    /// @notice Total number of unique investors
    /// @dev Used for compliance tracking and reporting
    uint256 public investorCount;
    
    /// @notice Allow beneficiary to be different from sender
    /// @dev When true, enables third-party investments on behalf of others
    bool public allowBeneficialInvestments;
    
    // ============== Future storage slot reservation ==============
    
    /// @notice Reserved storage space to allow for layout changes in the future.
    /// @dev This gap is reserved for future variable additions and should not be used.
    /// The size is arbitrary but should be large enough to accommodate future needs.
    uint256[50] private __gap;
}