// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../libraries/Withdrawal.sol";

/**
 * @title ISignedWithdraw
 * @notice Interface for signed withdrawal functionality
 */
interface ISignedWithdraw {
    
    /**
     * @notice Execute a signed withdrawal from an investor
     * @param withdrawal The withdrawal details signed by the investor
     * @param signature The EIP-712 signature from the investor
     */
    function executeSignedWithdrawal(
        Withdrawal.WithdrawalInfo calldata withdrawal,
        bytes calldata signature
    ) external;
    
    /**
     * @notice Verify a signature against a withdrawal
     * @param withdrawal The withdrawal that was signed
     * @param signature The signature to verify
     * @param expectedSigner The address that should have signed the withdrawal
     * @return True if the signature is valid, false otherwise
     */
    function isValidSignature(
        Withdrawal.WithdrawalInfo calldata withdrawal,
        bytes calldata signature,
        address expectedSigner
    ) external view returns (bool);
    
    /**
     * @notice Get the EIP-712 domain separator
     * @return The domain separator
     */
    function getDomainSeparator() external view returns (bytes32);
    
    /**
     * @notice Get the EIP-712 type hash for WithdrawalInfo
     * @return The type hash
     */
    function getWithdrawalTypeHash() external view returns (bytes32);
    
    /**
     * @notice Hash a withdrawal using EIP-712
     * @param withdrawal The withdrawal to hash
     * @return The EIP-712 hash of the withdrawal
     */
    function hashWithdrawal(Withdrawal.WithdrawalInfo calldata withdrawal) external view returns (bytes32);
    
    /**
     * @notice Get the current nonce for an investor
     * @param investor The investor address
     * @return The current nonce
     */
    function getNonce(address investor) external view returns (uint256);
}