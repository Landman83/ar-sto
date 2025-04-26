// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "../libraries/Order.sol";
import "../interfaces/ISignatures.sol";

/**
 * @title Signatures
 * @notice Implementation of signature verification functionality
 * @dev Uses EIP-712 for typed data signing and verification
 */
contract Signatures is EIP712, ISignatures {
    // Use the ORDER_TYPEHASH from the Order library
    bytes32 public constant ORDER_TYPEHASH = Order.ORDER_TYPEHASH;
    
    /**
     * @dev Constructor for Signatures
     * @param name The name to use in the EIP-712 domain
     * @param version The version to use in the EIP-712 domain
     */
    constructor(string memory name, string memory version) EIP712(name, version) {}
    
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
    ) external view override returns (bool) {
        bytes32 orderHash = hashOrder(order);
        address recoveredSigner = recoverSigner(orderHash, signature);
        return recoveredSigner == expectedSigner;
    }
    
    /**
     * @notice Get the EIP-712 domain separator
     * @return The domain separator
     */
    function getDomainSeparator() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }
    
    /**
     * @notice Get the EIP-712 type hash for OrderInfo
     * @return The type hash
     */
    function getOrderTypeHash() external pure override returns (bytes32) {
        return ORDER_TYPEHASH;
    }
    
    /**
     * @notice Hash an order using EIP-712
     * @param order The order to hash
     * @return The EIP-712 hash of the order
     */
    function hashOrder(Order.OrderInfo calldata order) public view override returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(abi.encode(
                ORDER_TYPEHASH,
                order.investor,
                order.investmentToken,
                order.investmentTokenAmount,
                order.securityTokenAmount,
                order.nonce
            ))
        );
    }
    
    /**
     * @notice Recover the signer from a signature and hash
     * @param hash The hash that was signed
     * @param signature The signature bytes
     * @return The recovered signer address
     */
    function recoverSigner(bytes32 hash, bytes calldata signature) public pure override returns (address) {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        
        // EIP-2 standardized the signature format
        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "Invalid signature 'v' value");
        
        return ecrecover(hash, v, r, s);
    }
}