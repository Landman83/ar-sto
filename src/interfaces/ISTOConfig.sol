// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title ISTOConfig - Interface for the STO Configuration Manager
 * @notice Defines the contract responsible for storing and managing all STO configuration
 * @dev This interface explicitly defines the configuration parameters and fund tracking
 *      functionality. The STOConfig serves as the single source of truth for all
 *      STO parameters, eliminating duplication across different components.
 */
interface ISTOConfig {
    /**
     * @notice Enum for fund raise types
     */
    enum FundRaiseType { ETH, POLY, DAI, USDT, USDC, ERC20 }

    /**
     * @notice Configure just the time parameters for the offering
     * @param _startTime Start time of the offering
     * @param _endTime End time of the offering
     * @param _investmentToken Address of the token used for investment
     * @dev Only callable by the STO contract
     *      Updates the time window for investments and the investment token
     */
    function configureTimeParameters(
        uint256 _startTime,
        uint256 _endTime,
        address _investmentToken
    ) external;
    
    /**
     * @notice Configure the offering parameters
     * @param _startTime Start time of the offering
     * @param _endTime End time of the offering
     * @param _hardCap Hard cap for the offering
     * @param _softCap Soft cap for the offering
     * @param _rate Exchange rate for investment tokens to security tokens
     * @param _fundsReceiver Address to receive investment funds
     * @param _investmentToken Address of the token used for investment
     * @dev Only callable by the STO contract
     *      Sets all core parameters for the STO
     */
    function configure(
        uint256 _startTime,
        uint256 _endTime,
        uint256 _hardCap,
        uint256 _softCap,
        uint256 _rate,
        address payable _fundsReceiver,
        address _investmentToken
    ) external;
    
    /**
     * @notice Set the fund raise types
     * @param _fundRaiseTypes Array of fund raise types
     * @dev Only callable by the STO contract
     *      Defines which token types can be used for investment
     */
    function setFundRaiseTypes(FundRaiseType[] calldata _fundRaiseTypes) external;
    
    /**
     * @notice Update the funds raised for a specific type
     * @param _fundRaiseType The fund raise type
     * @param _amount Amount to add (or subtract if negative)
     * @dev Only callable by the STO contract
     *      Updates the tracked amount of funds raised
     *      Negative values are used for withdrawals/refunds
     */
    function updateFundsRaised(uint8 _fundRaiseType, int256 _amount) external;
    
    /**
     * @notice Increment the investor count
     * @dev Only callable by the STO contract
     *      Tracks the number of unique investors in the offering
     */
    function incrementInvestorCount() external;
    
    /**
     * @notice Set whether to allow beneficial investments
     * @param _allowBeneficialInvestments Whether to allow beneficial investments
     * @dev Only callable by the STO contract
     *      Controls whether investors can purchase tokens for others
     */
    function setAllowBeneficialInvestments(bool _allowBeneficialInvestments) external;
    
    /**
     * @notice Get the hard cap
     * @return The hard cap
     * @dev Returns the maximum number of tokens available in the offering
     */
    function getHardCap() external view returns (uint256);
    
    /**
     * @notice Get the soft cap
     * @return The soft cap
     * @dev Returns the minimum number of tokens that must be sold for success
     */
    function getSoftCap() external view returns (uint256);
    
    /**
     * @notice Check if soft cap is reached
     * @return Whether the soft cap is reached
     * @dev Compares total funds raised against the soft cap
     *      This is the authoritative source for soft cap status
     */
    function isSoftCapReached() external view returns (bool);
    
    /**
     * @notice Check if hard cap is reached
     * @return Whether the hard cap is reached
     * @dev Compares total funds raised against the hard cap
     *      This is the authoritative source for hard cap status
     */
    function isHardCapReached() external view returns (bool);
    
    /**
     * @notice Get the total funds raised
     * @return The total funds raised
     * @dev Sums all fund types to calculate total raised
     *      This is the authoritative source for funds raised
     */
    function getTotalFundsRaised() external view returns (uint256);
    
    /**
     * @notice Check if an offering is active
     * @return Whether the offering is active
     * @dev Returns true if within time window and hard cap not reached
     *      This is the authoritative source for offering activity status
     */
    function isOfferingActive() external view returns (bool);
    
    /**
     * @notice Get the start time of the offering
     * @return The start time timestamp
     */
    function startTime() external view returns (uint256);
    
    /**
     * @notice Get the end time of the offering
     * @return The end time timestamp
     */
    function endTime() external view returns (uint256);
    
    /**
     * @notice Get the current rate
     * @return The exchange rate
     */
    function rate() external view returns (uint256);
    
    /**
     * @notice Get the funds receiver address
     * @return The funds receiver address
     */
    function fundsReceiver() external view returns (address payable);
    
    /**
     * @notice Get the investment token address
     * @return The investment token address
     */
    function investmentToken() external view returns (address);
    
    /**
     * @notice Get the current investor count
     * @return The investor count
     */
    function investorCount() external view returns (uint256);
    
    /**
     * @notice Get whether beneficial investments are allowed
     * @return Whether beneficial investments are allowed
     */
    function allowBeneficialInvestments() external view returns (bool);
    
    /**
     * @notice Get the funds raised for a specific type
     * @param _fundRaiseType The fund raise type
     * @return The amount of funds raised for the specified type
     */
    function fundsRaised(uint8 _fundRaiseType) external view returns (uint256);
    
    /**
     * @notice Check if a specific fund raise type is enabled
     * @param _fundRaiseType The fund raise type
     * @return Whether the fund raise type is enabled
     */
    function fundRaiseTypes(uint8 _fundRaiseType) external view returns (bool);
    
    /**
     * @notice Get the security token address
     * @return The security token address
     */
    function securityToken() external view returns (address);
    
    /**
     * @notice Get whether this is a Rule 506c offering
     * @return Whether this is a Rule 506c offering
     */
    function isRule506cOffering() external view returns (bool);
}