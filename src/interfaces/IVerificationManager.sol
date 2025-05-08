// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title IVerificationManager
 * @notice Interface for the contract responsible for managing investor verification status
 * @dev This interface defines the contract that tracks investor verification for
 *      regulatory compliance purposes. The VerificationManager serves as the source of truth
 *      for investor verification status and provides integration with external attribute registries.
 *
 * Dependencies:
 * - May integrate with an external AttributeRegistry contract for verification status
 * - Used by the CappedSTO contract to verify investor status before allowing investments
 * - Used by Compliance contract to check investor attributes
 */
interface IVerificationManager {
    /**
     * @notice Check if an investor is verified
     * @param _investor The address of the investor to check
     * @return Whether the investor is verified
     * @dev This is the authoritative source for verification status
     *      For Rule506c offerings, this verification is required before investing
     *      The implementation checks both internal verification and attribute registry status
     *      Returns true for all investors in non-Rule506c offerings
     */
    function isInvestorVerified(address _investor) external view returns (bool);
    
    /**
     * @notice Add an investor to the verified list (manual verification)
     * @param _investor The address of the investor to verify
     * @dev Only callable by the STO contract with OPERATOR_ROLE
     *      Sets the investor as verified in the internal mapping
     *      Emits an InvestorVerified event
     *      Removes from pending list if present
     */
    function verifyInvestor(address _investor) external;
    
    /**
     * @notice Add multiple investors to the verified list
     * @param _investors Array of investor addresses to verify
     * @dev Only callable by the STO contract with OPERATOR_ROLE
     *      More gas-efficient than calling verifyInvestor multiple times
     *      Used for batch onboarding verified investors
     */
    function batchVerifyInvestors(address[] calldata _investors) external;
    
    /**
     * @notice Remove an investor from the verified list
     * @param _investor The address of the investor to unverify
     * @dev Only callable by the STO contract with OPERATOR_ROLE
     *      Sets the investor as not verified in the internal mapping
     *      Emits an InvestorVerified event with false status
     *      Useful when an investor's verification expires or is revoked
     */
    function unverifyInvestor(address _investor) external;
    
    /**
     * @notice Request verification with custom data
     * @param _investor The address of the investor requesting verification
     * @param _data Additional verification data (e.g., document hash)
     * @dev Can be called by the investor themselves or the STO contract
     *      Adds the investor to the pending verification list
     *      Stores verification data for off-chain processing
     *      Emits a VerificationRequested event
     */
    function requestVerification(address _investor, bytes32 _data) external;
    
    /**
     * @notice Get all pending verification requests
     * @return Array of addresses with pending verification
     * @dev Returns all addresses that have requested verification but not yet been verified
     *      Used by off-chain processes to identify investors needing verification
     *      May return a large array for offerings with many pending verifications
     */
    function getPendingVerifications() external view returns (address[] memory);
    
    /**
     * @notice Check if an investor has a pending verification
     * @param _investor The address of the investor to check
     * @return Whether the investor has a pending verification
     * @dev Returns true if the investor has requested verification but not yet been verified
     *      Used by the UI to show appropriate status to investors
     */
    function hasPendingVerification(address _investor) external view returns (bool);
    
    /**
     * @notice Set the attribute registry address
     * @param _attributeRegistry The address of the attribute registry
     * @dev Only callable by the STO contract with OPERATOR_ROLE
     *      Updates the reference to the external attribute registry
     *      The attribute registry provides an additional source for verification status
     *      Emits an AttributeRegistryUpdated event
     */
    function setAttributeRegistry(address _attributeRegistry) external;
    
    /**
     * @notice Update the pending verification list to remove verified investors
     * @dev Only callable by the STO contract with OPERATOR_ROLE
     *      Maintenance function to clean up the pending list
     *      Removes investors who have been verified since requesting
     *      Helps keep the pending list accurate and gas-efficient
     */
    function cleanupPendingList() external;
    
    /**
     * @notice Get the current attribute registry address
     * @return The address of the attribute registry
     * @dev Returns the current attribute registry used for verification
     */
    function attributeRegistry() external view returns (address);
}