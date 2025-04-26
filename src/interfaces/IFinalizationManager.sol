// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Interface for the Finalization Manager
 * @notice Defines functionality for managing STO finalization
 */
interface IFinalizationManager {
    /**
     * @notice Finalize the offering
     * @param _endTime The end time of the offering
     * @param _hardCapReached Whether the hard cap has been reached
     * @param _investors Array of all investor addresses
     * @return softCapReached Whether the soft cap was reached
     */
    function finalize(
        uint256 _endTime,
        bool _hardCapReached,
        address[] calldata _investors
    ) external returns (bool softCapReached);
    
    /**
     * @notice Issue tokens to a specific investor
     * @param _investor Address of the investor
     * @param _amount Amount of tokens to issue
     */
    function issueTokens(address _investor, uint256 _amount) external;
    
    /**
     * @notice Helper function for the owner to manually mint tokens to an investor
     * @param _investor The address of the investor to receive tokens
     * @param _amount The amount of tokens to mint
     * @param _owner The address of the owner performing the minting
     */
    function ownerMintTokens(address _investor, uint256 _amount, address _owner) external;
    
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