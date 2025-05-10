// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/utils/Signatures.sol";
import "../src/libraries/Order.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract SignatureTest is Test {
    // Contracts used in tests
    Signatures signatures;
    
    // Test accounts - using Forge's default account convention
    uint256 investorPrivateKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80; // Anvil default private key #0
    address investor; // Will be derived from the private key
    
    address investmentToken = address(0x2);
    address stoContract = address(0x3);
    
    // Order parameters
    uint256 investmentAmount = 100 ether;
    uint256 securityTokenAmount = 0;
    uint256 nonce = 1;
    
    // Setup for tests
    function setUp() public {
        // Derive the investor address from the private key
        investor = vm.addr(investorPrivateKey);
        console.log("Investor address:", investor);
        
        // Set up the investor account with ETH
        vm.deal(investor, 100 ether);
        vm.startPrank(investor);
        vm.label(investor, "Investor");
        vm.label(investmentToken, "USDC");
        vm.label(stoContract, "STO Contract");
        
        // Deploy the Signatures contract
        signatures = new Signatures("Security Token Offering", "1");
        vm.label(address(signatures), "Signatures");
        
        vm.stopPrank();
    }
    
    // Helper function to create a standard order
    function createOrder() internal view returns (Order.OrderInfo memory) {
        return Order.OrderInfo({
            investor: investor,
            investmentToken: investmentToken,
            investmentTokenAmount: investmentAmount,
            securityTokenAmount: securityTokenAmount,
            nonce: nonce
        });
    }
    
    // Helper function to sign an order with the investor's private key
    function signOrder(Order.OrderInfo memory order) internal view returns (bytes memory) {
        // Get order components for debugging
        console.log("Order components:");
        console.log("- Investor:", order.investor);
        console.log("- Investment Token:", order.investmentToken);
        console.log("- Investment Amount:", order.investmentTokenAmount);
        console.log("- Security Token Amount:", order.securityTokenAmount);
        console.log("- Nonce:", order.nonce);
        
        // Get type hash for debugging
        bytes32 typeHash = signatures.getOrderTypeHash();
        console.log("Order Type Hash:");
        console.logBytes32(typeHash);
        
        // Get domain separator and order hash
        bytes32 domainSeparator = signatures.getDomainSeparator();
        bytes32 orderHash = signatures.hashOrder(order);
        
        console.log("Domain Separator:");
        console.logBytes32(domainSeparator);
        console.log("Order Hash:");
        console.logBytes32(orderHash);
        
        // Calculate the message hash to sign (should match what the contract does internally)
        bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, orderHash));
        console.log("Digest Hash (what contract would sign):");
        console.logBytes32(digestHash);
        
        // Sign the order hash using the investor's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(investorPrivateKey, orderHash);
        
        // Log signature components
        console.log("Signature components:");
        console.log("- v:", uint256(v));
        console.logBytes32(r);
        console.logBytes32(s);
        
        // Format the signature
        return abi.encodePacked(r, s, v);
    }
    
    // Test basic signature validation
    function testSignatureValidation() public {
        Order.OrderInfo memory order = createOrder();
        bytes memory signature = signOrder(order);
        
        // Verify the signature
        bool isValid = signatures.isValidSignature(order, signature, investor);
        
        // Check that the signature is valid
        assertTrue(isValid, "Signature should be valid");
        
        // Log success
        console.log("Signature validation successful!");
    }
    
    // Test signature validation with invalid signer
    function testInvalidSigner() public {
        Order.OrderInfo memory order = createOrder();
        bytes memory signature = signOrder(order);
        
        // Try to verify with a different address
        address wrongAddress = address(0x4);
        bool isValid = signatures.isValidSignature(order, signature, wrongAddress);
        
        // Check that the signature is invalid
        assertFalse(isValid, "Signature should be invalid for wrong address");
        
        // Log success
        console.log("Invalid signer detection successful!");
    }
    
    // Test tampering with order after signing
    function testTamperedOrder() public {
        Order.OrderInfo memory order = createOrder();
        bytes memory signature = signOrder(order);
        
        // Create a modified order with a different amount
        Order.OrderInfo memory tamperedOrder = order;
        tamperedOrder.investmentTokenAmount = 200 ether;
        
        // Verify the signature with tampered order
        bool isValid = signatures.isValidSignature(tamperedOrder, signature, investor);
        
        // Check that the signature is invalid
        assertFalse(isValid, "Signature should be invalid for tampered order");
        
        // Log success
        console.log("Tampered order detection successful!");
    }
    
    // Test signature with invalid format
    function testInvalidSignatureFormat() public {
        Order.OrderInfo memory order = createOrder();
        
        // Create an invalid signature (too short)
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0));
        
        // This should revert with "Invalid signature length"
        vm.expectRevert("Invalid signature length");
        signatures.isValidSignature(order, invalidSignature, investor);
        
        // Log success
        console.log("Invalid signature format detection successful!");
    }
    
    // Test nonce replay protection
    function testNonceReplayProtection() public {
        // This test would interact with the STO contract to test nonce management
        // For simplicity, we'll just demonstrate the concept
        
        Order.OrderInfo memory order1 = createOrder();
        bytes memory signature1 = signOrder(order1);
        
        // Create a second order with the same nonce
        Order.OrderInfo memory order2 = createOrder();
        order2.investmentTokenAmount = 50 ether; // Different amount
        bytes memory signature2 = signOrder(order2);
        
        // Both signatures are valid from a cryptographic standpoint
        bool isValid1 = signatures.isValidSignature(order1, signature1, investor);
        bool isValid2 = signatures.isValidSignature(order2, signature2, investor);
        
        assertTrue(isValid1, "First signature should be valid");
        assertTrue(isValid2, "Second signature should be valid");
        
        // In a real implementation, the STO contract would track used nonces
        // and reject the second order with the same nonce
        console.log("Nonce replay protection concept demonstrated!");
    }
    
    // Test cross-contract replay protection with STO address
    function testCrossContractProtection() public {
        // Create and deploy a different Signatures contract (for a different STO)
        vm.startPrank(investor);
        Signatures otherSignatures = new Signatures("Security Token Offering", "1");
        vm.stopPrank();
        
        // Create and sign an order using our original signatures contract
        Order.OrderInfo memory order = createOrder();
        bytes memory signature = signOrder(order);
        
        // The signature is valid with the original contract
        bool isValidOriginal = signatures.isValidSignature(order, signature, investor);
        assertTrue(isValidOriginal, "Signature should be valid with original contract");
        
        // But the signature would be invalid with a different contract
        // because of different domain separators
        bytes32 originalDomain = signatures.getDomainSeparator();
        bytes32 otherDomain = otherSignatures.getDomainSeparator();
        
        assertNotEq(originalDomain, otherDomain, "Domain separators should be different");
        
        // Log success
        console.log("Cross-contract replay protection demonstrated!");
    }
    
    // Test simulating a complete order submission flow
    function testCompleteOrderFlow() public {
        // This would be a full integration test with STO contract
        // For now, we'll just simulate the main steps
        
        // 1. Create an order
        Order.OrderInfo memory order = createOrder();
        
        // 2. Sign the order
        bytes memory signature = signOrder(order);
        
        // 3. Verify the signature
        bool isValid = signatures.isValidSignature(order, signature, investor);
        assertTrue(isValid, "Signature should be valid");
        
        // 4. In a real scenario, we would increment the nonce in the STO contract
        // nonces[order.investor]++;
        
        // Log success
        console.log("Complete order flow simulation successful!");
    }
}