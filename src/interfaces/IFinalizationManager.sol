// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title IFinalizationManager - Interface for the Finalization Manager
 * @notice Defines the contract responsible for all offering finalization operations
 * @dev This interface explicitly defines the finalization process and token distribution
 *      mechanisms. The FinalizationManager serves as the source of truth for finalization
 *      status, token distribution tracking, and refund processing.
 *
 * Dependencies:
 * - Requires initialized Escrow contract to handle fund distribution
 * - Requires Minting contract to mint and deliver tokens
 * - Requires Refund contract to process refunds
 * - Works with security token for token issuance
 * - Requires STOConfig for configuration parameters and cap tracking
 */
interface IFinalizationManager {
    /**
     * @notice Finalize the offering
     * @param _endTime The end time of the offering
     * @param _hardCapReached Whether the hard cap has been reached
     * @param _investors Array of all investor addresses
     * @return softCapReached Whether the soft cap was reached
     * @dev This is the main finalization function that:
     *      1. Determines if the offering was successful (soft cap reached)
     *      2. Finalizes the escrow
     *      3. Either distributes tokens (if successful) or processes refunds (if unsuccessful)
     *      4. Transfers funds to the wallet (if successful)
     *      Only executable after the offering has ended or when hard cap is reached
     *      Calling this multiple times will be a no-op after the first successful execution
     */
    function finalize(
        uint256 _endTime,
        bool _hardCapReached,
        address[] calldata _investors
    ) external returns (bool softCapReached);

    /**
     * @notice Process minting for all investors after escrow is finalized
     * @param _investors Array of all investor addresses
     * @dev This function handles the token minting part of finalization
     *      It's separated from finalize() to allow the STO contract to call escrow.finalize() directly
     *      Only callable when soft cap is reached and escrow is already finalized
     */
    function processMinting(address[] calldata _investors) external;

    /**
     * @notice Process refunds for all investors after escrow is finalized
     * @param _investors Array of all investor addresses
     * @dev This function handles the refund part of finalization
     *      It's separated from finalize() to allow the STO contract to call escrow.finalize() directly
     *      Only callable when soft cap is NOT reached and escrow is already finalized
     */
    function processRefunds(address[] calldata _investors) external;
    
    /**
     * @notice Issue tokens to a specific investor
     * @param _investor Address of the investor
     * @param _amount Amount of tokens to issue
     * @dev Only callable by the STO contract, typically via the Minting contract
     *      Calls the security token to mint new tokens to the investor
     *      For Rule506c tokens, may require special permissions
     *      Marks the investor as having received tokens to prevent double issuance
     */
    function issueTokens(address _investor, uint256 _amount) external;
    
    /**
     * @notice Helper function for the owner to manually mint tokens to an investor
     * @param _investor The address of the investor to receive tokens
     * @param _amount The amount of tokens to mint
     * @param _owner The address of the owner performing the minting
     * @dev Only callable by the STO contract for Rule506c offerings
     *      Allows the token owner to mint tokens directly
     *      Used when the STO contract itself is not an agent of the token
     *      The owner must have permission to mint tokens on the security token
     */
    function ownerMintTokens(address _investor, uint256 _amount, address _owner) external;
    
    /**
     * @notice Check if an investor has received their tokens
     * @param _investor Address of the investor
     * @return Whether the investor has received tokens
     * @dev This is the authoritative source for token issuance status
     *      Used to prevent double issuance of tokens
     *      Returns true once tokens have been successfully delivered to the investor
     */
    function hasReceivedTokens(address _investor) external view returns (bool);
    
    /**
     * @notice Check if an investor has claimed their refund
     * @param _investor Address of the investor
     * @return Whether the investor has claimed a refund
     * @dev This is the authoritative source for refund claim status
     *      Used to prevent double refunds
     *      Returns true once a refund has been successfully processed for the investor
     */
    function hasClaimedRefund(address _investor) external view returns (bool);
    
    /**
     * @notice Check if the offering has been finalized
     * @return Whether the offering has been finalized
     * @dev Returns the finalization status directly from the escrow
     *      This is the authoritative source for finalization status
     */
    function isFinalized() external view returns (bool);
    
    /**
     * @notice Check if soft cap was reached
     * @return Whether the soft cap was reached
     * @dev This is the authoritative source for the soft cap status
     *      Returns true if the offering raised enough funds to meet the soft cap
     */
    function isSoftCapReached() external view returns (bool);
    
    /**
     * @notice Set the STOConfig contract 
     * @param _stoConfig Address of the STOConfig contract
     * @dev Only callable by the STO contract
     *      The STOConfig contract is the authoritative source for configuration parameters
     *      Used for all cap validation, fund tracking, and offering parameters
     */
    function setSTOConfig(address _stoConfig) external;
}