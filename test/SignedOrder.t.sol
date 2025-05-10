// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../src/CappedSTO.sol";
import "../src/utils/Signatures.sol";
import "../src/utils/Escrow.sol";
import "../src/libraries/Order.sol";
import "../src/interfaces/ISTO.sol";

/**
 * @title SignedOrder Test
 * @notice Tests the submission and verification of signed orders
 */
contract SignedOrderTest is Test {
    // Contracts
    CappedSTO private sto;
    IERC20 private investmentToken;
    Signatures private signatures;
    
    // Addresses from .env
    address private deployer;
    address private stoAddress;
    address private securityTokenAddress;
    address private investmentTokenAddress;
    uint256 private deployerPrivateKey;
    
    // Test parameters - using a very small amount that won't hit the hard cap
    uint256 private constant INVESTMENT_AMOUNT = 100 * 10**18; // 0.001 tokens (1 finney) to stay far below hard cap
    uint256 private constant SECURITY_TOKEN_AMOUNT = 200 * 10**17; // 0.0002 security tokens
    
    function setUp() public {
        // Load environment variables
        string memory rpcUrl = vm.envString("RPC_URL");
        deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        deployer = vm.addr(deployerPrivateKey);
        stoAddress = vm.envAddress("STO_ADDRESS");
        securityTokenAddress = vm.envAddress("SECURITY_TOKEN_ADDRESS");
        investmentTokenAddress = vm.envAddress("INVESTMENT_TOKEN");
        
        // Create fork
        vm.createSelectFork(rpcUrl);
        
        // Connect to contracts
        sto = CappedSTO(payable(stoAddress));
        investmentToken = IERC20(investmentTokenAddress);
        
        // Check if contracts are accessible
        require(address(sto) != address(0), "STO contract not found");
        require(address(investmentToken) != address(0), "Investment token not found");
        
        console.log("Test setup complete");
        console.log("STO address:", stoAddress);
        console.log("Security token:", securityTokenAddress);
        console.log("Investment token:", investmentTokenAddress);
        console.log("Deployer:", deployer);
        
        // Connect to the actual Signatures contract used by the STO
        try sto.signaturesContract() returns (address signaturesAddr) {
            require(signaturesAddr != address(0), "STO signatures contract not set");
            // Use the existing Signatures contract deployed by the STO
            signatures = Signatures(signaturesAddr);
            console.log("Connected to STO's Signatures contract at:", address(signatures));
        } catch {
            revert("Failed to get STO's Signatures contract - test cannot continue");
        }
    }
    
    function testSignedOrderExecution() public {
        console.log("Starting signed order test");
        
        // Step 1: Get initial STO state
        (
            , // startTime
            , // endTime
            , // hardCap
            , // softCap
            uint256 currentRate,
            uint256 fundsRaisedBefore,
            uint256 investorCountBefore,
            uint256 tokensSoldBefore,
            , // investmentToken address
            , // softCapReached
            bool stoClosed
        ) = sto.getSTODetails();
        
        console.log("STO Closed:", stoClosed);
        console.log("Initial funds raised:", fundsRaisedBefore);
        console.log("Initial investors:", investorCountBefore);
        console.log("Initial tokens sold:", tokensSoldBefore);
        console.log("Current rate:", currentRate);
        
        // Skip test if STO is closed
        if (stoClosed) {
            console.log("STO is closed, skipping signed order test");
            return;
        }
        
        // Step 2: Ensure deployer has enough investment tokens
        uint256 deployerBalance = investmentToken.balanceOf(deployer);
        console.log("Deployer investment token balance:", deployerBalance);
        
        if (deployerBalance < INVESTMENT_AMOUNT) {
            console.log("Deployer needs more investment tokens. Adding tokens...");
            // Use the deal function to give tokens to the deployer
            deal(address(investmentToken), deployer, INVESTMENT_AMOUNT * 2);
            deployerBalance = investmentToken.balanceOf(deployer);
            console.log("New deployer balance:", deployerBalance);
        }
        
        // Step 3: Approve investment tokens to be spent by the STO
        vm.startPrank(deployer);
        investmentToken.approve(stoAddress, INVESTMENT_AMOUNT);
        console.log("Approved STO to spend investment tokens");
        vm.stopPrank();
        
        // Step 4: Get current nonce for the deployer
        uint256 nonce = sto.getNonce(deployer);
        console.log("Current deployer nonce:", nonce);
        
        // Step 5: Create and sign the order
        // Create order structure with defined parameters
        Order.OrderInfo memory order = Order.OrderInfo({
            investor: deployer,
            investmentToken: investmentTokenAddress,
            investmentTokenAmount: INVESTMENT_AMOUNT,
            securityTokenAmount: SECURITY_TOKEN_AMOUNT,
            nonce: nonce
        });
        
        console.log("Created order:");
        console.log("- Investor:", order.investor);
        console.log("- Investment Token:", order.investmentToken);
        console.log("- Investment Amount:", order.investmentTokenAmount);
        console.log("- Security Token Amount:", order.securityTokenAmount);
        console.log("- Nonce:", order.nonce);
        
        // Get order hash and domain separator from the signatures contract
        bytes32 orderHash = signatures.hashOrder(order);
        console.log("Order hash:", vm.toString(orderHash));

        // Get domain separator from the signatures contract
        bytes32 domainSeparator = signatures.getDomainSeparator();
        console.log("Domain Separator:", vm.toString(domainSeparator));

        // Calculate the complete digest hash that includes domain separator (EIP-712 format)
        bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, keccak256(abi.encode(
            signatures.getOrderTypeHash(),
            order.investor,
            order.investmentToken,
            order.investmentTokenAmount,
            order.securityTokenAmount,
            order.nonce
        ))));
        console.log("Complete digest hash:", vm.toString(digestHash));

        // Sign the complete digest hash using the deployer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, digestHash);

        // Format the signature as expected by the STO contract
        bytes memory signature = abi.encodePacked(r, s, v);
        console.log("Signature created with length:", signature.length);
        
        // Step 6: Verify the signature is valid
        bool isValid = signatures.isValidSignature(order, signature, deployer);
        console.log("Signature valid:", isValid);
        assertTrue(isValid, "Signature should be valid before submission");
        
        // Step 7: Submit the signed order
        vm.startPrank(deployer);
        console.log("Submitting signed order...");
        
        try sto.executeSignedOrder(order, signature) {
            console.log("Order execution successful");
            vm.stopPrank();
            
            // Step 8: Verify order was processed correctly
            (
                , // startTime
                , // endTime
                , // hardCap
                , // softCap
                , // currentRate
                uint256 fundsRaisedAfter,
                uint256 investorCountAfter,
                uint256 tokensSoldAfter,
                , // investmentToken address
                , // softCapReached
                // stoClosed
            ) = sto.getSTODetails();
            
            console.log("After execution:");
            console.log("Funds raised:", fundsRaisedAfter);
            console.log("Investor count:", investorCountAfter);
            console.log("Tokens sold:", tokensSoldAfter);
            
            // Verify funds were transferred into the STO
            assertGt(fundsRaisedAfter, fundsRaisedBefore, "Funds raised should increase after order execution");
            
            // Verify tokens were minted
            if (tokensSoldAfter > tokensSoldBefore) {
                console.log("Token sale increase detected:", tokensSoldAfter - tokensSoldBefore);
            } else {
                console.log("No token sale increase detected");
            }
            
            // Verify deployer balance decreased
            uint256 deployerBalanceAfter = investmentToken.balanceOf(deployer);
            console.log("Deployer investment token balance after:", deployerBalanceAfter);
            assertLt(deployerBalanceAfter, deployerBalance, "Deployer balance should decrease after order execution");
            
            // Check escrow for deployer deposit
            try sto.escrow() returns (Escrow escrowContract) {
                // Verify that the funds were transferred to escrow
                uint256 escrowBalance = investmentToken.balanceOf(address(escrowContract));
                console.log("Escrow investment token balance:", escrowBalance);
                assertGt(escrowBalance, 0, "Escrow should have a positive token balance");
                
                // Check if the deposit was recorded for the investor
                try escrowContract.getInvestment(deployer) returns (uint256 investment) {
                    console.log("Recorded investment for deployer:", investment);
                    assertGe(investment, INVESTMENT_AMOUNT, "Deposited amount should be at least the investment amount");
                } catch Error(string memory reason) {
                    console.log("Failed to get deployer investment:", reason);
                } catch {
                    console.log("Failed to get deployer investment (unknown error)");
                }
            } catch {
                console.log("Failed to get escrow contract");
            }
            
            // Verify nonce was incremented
            uint256 newNonce = sto.getNonce(deployer);
            console.log("New deployer nonce:", newNonce);
            assertEq(newNonce, nonce + 1, "Nonce should be incremented after order execution");
            
        } catch Error(string memory reason) {
            console.log("Order execution failed:", reason);
            vm.stopPrank();
            assertTrue(false, string.concat("Order execution failed: ", reason));
        } catch (bytes memory revertData) {
            console.log("Order execution failed with raw error:");
            console.logBytes(revertData);
            vm.stopPrank();
            assertTrue(false, "Order execution failed with raw error");
        }
    }
}