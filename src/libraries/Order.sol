// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Order
 * @notice Library defining the Order struct used in the STO system
 */
library Order {
    /**
     * @notice Order struct representing a trade order
     * @param investor The address of the order investor
     * @param investmentToken The token address the investor is offering
     * @param investmentTokenAmount The amount of tokens the investor is offering
     * @param securityTokenAmount The amount of tokens the investor wants in return
     * @param nonce The investor's nonce to prevent replay attacks
     */
    struct OrderInfo {
        address investor;
        address investmentToken;
        uint256 investmentTokenAmount;
        uint256 securityTokenAmount;
        uint256 nonce;
    }
    
    /**
     * @dev EIP-712 Type Hash for OrderInfo struct
     */
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "OrderInfo(address investor,address investmentToken,uint256 investmentTokenAmount,uint256 securityTokenAmount,uint256 nonce)"
    );
}