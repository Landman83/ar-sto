// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../libraries/Order.sol";

/**
 * @title ISignatures
 * @notice Interface for signature verification functionality
 */
interface ISignatures {
    /**
     * @notice Verifies a signature against an order
     * @param order The order that was signed
     * @param signature The signature to verify
     * @param expectedSigner The address that should have signed the order
     * @return True if the signature is valid, false otherwise
     */
    function isValidSignature(
        Order.OrderInfo calldata order,
        bytes calldata signature,
        address expectedSigner
    ) external view returns (bool);
    
    /**
     * @notice Get the EIP-712 domain separator
     * @return The domain separator
     */
    function getDomainSeparator() external view returns (bytes32);
    
    /**
     * @notice Get the EIP-712 type hash for OrderInfo
     * @return The type hash
     */
    function getOrderTypeHash() external pure returns (bytes32);
    
    /**
     * @notice Hash an order using EIP-712
     * @param order The order to hash
     * @return The EIP-712 hash of the order
     */
    function hashOrder(Order.OrderInfo calldata order) external view returns (bytes32);
    
    /**
     * @notice Recover the signer from a signature and hash
     * @param hash The hash that was signed
     * @param signature The signature bytes
     * @return The recovered signer address
     */
    function recoverSigner(bytes32 hash, bytes calldata signature) external pure returns (address);
}