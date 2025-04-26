// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Attributes
 * @dev Library defining standard attribute types for compliance
 * @notice This mirrors the attribute types defined in the st-identity-registry library
 */
library Attributes {
    // Common attribute types
    bytes32 public constant KYC_VERIFIED = keccak256("KYC_VERIFIED");
    bytes32 public constant ACCREDITED_INVESTOR = keccak256("ACCREDITED_INVESTOR");
    bytes32 public constant COMPANY_INSIDER = keccak256("COMPANY_INSIDER");
    
    // Regional attributes
    bytes32 public constant US_PERSON = keccak256("US_PERSON");
    bytes32 public constant NON_US_PERSON = keccak256("NON_US_PERSON");
    
    // Custom attribute namespace
    function customAttribute(string memory name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("CUSTOM.", name));
    }
}