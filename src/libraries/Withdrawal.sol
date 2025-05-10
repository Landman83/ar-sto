// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Withdrawal
 * @notice Library defining the Withdrawal struct used in the STO system
 */
library Withdrawal {
    /**
     * @notice Withdrawal struct representing a withdrawal request
     * @param investor The address of the investor requesting withdrawal
     * @param investmentToken The token address being withdrawn
     * @param withdrawalAmount The amount of tokens to withdraw
     * @param nonce The investor's nonce to prevent replay attacks
     */
    struct WithdrawalInfo {
        address investor;
        address investmentToken;
        uint256 withdrawalAmount;
        uint256 nonce;
    }
    
    /**
     * @dev EIP-712 Type Hash for WithdrawalInfo struct
     */
    bytes32 public constant WITHDRAWAL_TYPEHASH = keccak256(
        "WithdrawalInfo(address investor,address investmentToken,uint256 withdrawalAmount,uint256 nonce)"
    );
}