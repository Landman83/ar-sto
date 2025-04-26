// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title IVerificationManager
 * @notice Interface for the VerificationManager contract
 */
interface IVerificationManager {
    /**
     * @notice Check if an investor is verified
     * @param _investor The address of the investor to check
     * @return Whether the investor is verified
     */
    function isInvestorVerified(address _investor) external view returns (bool);
    
    /**
     * @notice Add an investor to the verified list (manual verification)
     * @param _investor The address of the investor to verify
     */
    function verifyInvestor(address _investor) external;
    
    /**
     * @notice Add multiple investors to the verified list
     * @param _investors Array of investor addresses to verify
     */
    function batchVerifyInvestors(address[] calldata _investors) external;
    
    /**
     * @notice Remove an investor from the verified list
     * @param _investor The address of the investor to unverify
     */
    function unverifyInvestor(address _investor) external;
    
    /**
     * @notice Request verification with custom data
     * @param _investor The address of the investor requesting verification
     * @param _data Additional verification data (e.g., document hash)
     */
    function requestVerification(address _investor, bytes32 _data) external;
    
    /**
     * @notice Get all pending verification requests
     * @return Array of addresses with pending verification
     */
    function getPendingVerifications() external view returns (address[] memory);
    
    /**
     * @notice Check if an investor has a pending verification
     * @param _investor The address of the investor to check
     * @return Whether the investor has a pending verification
     */
    function hasPendingVerification(address _investor) external view returns (bool);
    
    /**
     * @notice Set the attribute registry address
     * @param _attributeRegistry The address of the attribute registry
     */
    function setAttributeRegistry(address _attributeRegistry) external;
    
    /**
     * @notice Update the pending verification list to remove verified investors
     */
    function cleanupPendingList() external;
}