// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../src/CappedSTO.sol";
import "../src/utils/Signatures.sol";
import "../src/utils/Escrow.sol";
import "../src/utils/Refund.sol";
import "../src/libraries/Withdrawal.sol";
import "../src/interfaces/ISTO.sol";
import "../src/utils/InvestmentManager.sol";
import "../src/mixins/PricingLogic.sol";

/**
 * @title SignedWithdrawalTest
 * @notice Tests the submission and verification of signed withdrawals
 */
contract SignedWithdrawalTest is Test {
    // Contracts
    CappedSTO private sto;
    IERC20 private investmentToken;
    Signatures private signatures;
    InvestmentManager private investmentManager;
    Escrow private escrow;
    Refund private refund;
    PricingLogic private pricingLogic;
    
    // Addresses from .env
    address private deployer;
    address private stoAddress;
    address private securityTokenAddress;
    address private investmentTokenAddress;
    uint256 private deployerPrivateKey;
    
    // Test parameters
    uint256 private constant DEPOSIT_AMOUNT = 1000 * 10**18; // 1000 tokens
    uint256 private constant WITHDRAWAL_SMALL = 250 * 10**18; // 250 tokens (less than deposit)
    uint256 private constant WITHDRAWAL_EXACT = 1000 * 10**18; // 1000 tokens (equal to deposit)
    uint256 private constant WITHDRAWAL_EXCESS = 1500 * 10**18; // 1500 tokens (more than deposit)
    uint256 private minInvestment;
    
    function setUp() public {
        // Load environment variables
        string memory rpcUrl = vm.envString("RPC_URL");
        deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        deployer = vm.addr(deployerPrivateKey);
        stoAddress = vm.envAddress("STO_ADDRESS");
        securityTokenAddress = vm.envAddress("SECURITY_TOKEN_ADDRESS");
        investmentTokenAddress = vm.envAddress("INVESTMENT_TOKEN");
        
        // Try to get min investment from environment
        try vm.envUint("MIN_INVESTMENT") returns (uint256 minInv) {
            // Convert from raw value to wei (assuming 18 decimals)
            minInvestment = minInv * 10**18;
            console.log("Min investment from env (wei):", minInvestment);
        } catch {
            // Default min investment if not specified
            minInvestment = 100 * 10**18; // 100 tokens
            console.log("Using default min investment (wei):", minInvestment);
        }
        
        // Adjust deposit amount if needed to be above min investment
        if (DEPOSIT_AMOUNT < minInvestment) {
            console.log("Warning: DEPOSIT_AMOUNT is less than minInvestment, tests may fail");
        }
        
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
        
        // Connect to the InvestmentManager
        try sto.getInvestmentManager() returns (address investmentManagerAddr) {
            require(investmentManagerAddr != address(0), "STO investment manager not set");
            investmentManager = InvestmentManager(investmentManagerAddr);
            console.log("Connected to STO's InvestmentManager at:", investmentManagerAddr);
        } catch {
            revert("Failed to get STO's InvestmentManager - test cannot continue");
        }
        
        // Connect to the Escrow
        try sto.escrow() returns (Escrow escrowContract) {
            escrow = escrowContract;
            console.log("Connected to STO's Escrow at:", address(escrow));
        } catch {
            revert("Failed to get STO's Escrow - test cannot continue");
        }
        
        // Connect to the Refund contract
        try sto.refund() returns (Refund refundContract) {
            refund = refundContract;
            console.log("Connected to STO's Refund at:", address(refund));
        } catch {
            revert("Failed to get STO's Refund - test cannot continue");
        }
        
        // Connect to the PricingLogic contract to get minimum investment
        try sto.pricingLogic() returns (PricingLogic pricingLogicContract) {
            pricingLogic = pricingLogicContract;
            console.log("Connected to STO's PricingLogic at:", address(pricingLogic));
            
            // Try to get minimum investment from contract
            try pricingLogic.minInvestment() returns (uint256 minInv) {
                console.log("Min investment from contract (wei):", minInv);
                if (minInv > 0) {
                    minInvestment = minInv; // Use contract's min investment if available
                }
            } catch {
                console.log("Could not get minimum investment from pricing logic");
            }
        } catch {
            console.log("Failed to get PricingLogic contract");
        }
        
        // Check STO state
        (
            , // startTime
            , // endTime
            , // hardCap
            , // softCap
            , // currentRate
            , // fundsRaised
            , // investorCount
            , // tokensSold
            , // investmentToken address
            , // softCapReached
            bool stoClosed
        ) = sto.getSTODetails();
        
        // Skip all tests if STO is closed
        if (stoClosed) {
            console.log("STO is closed, all tests will be skipped");
            return;
        }
        
        // Make deposit for all tests
        _makeDeposit();
    }
    
    /**
     * @notice Helper function to make a deposit
     * @dev Mints tokens and deposits them into the STO
     */
    function _makeDeposit() internal {
        console.log("Making initial deposit to ensure funds are available for withdrawal");
        
        // Get initial deposit status
        uint256 initialInvestment = 0;
        try escrow.getInvestment(deployer) returns (uint256 investment) {
            initialInvestment = investment;
            console.log("Initial investment in escrow:", initialInvestment);
        } catch {
            console.log("No initial investment found");
        }
        
        // Mint tokens for the test account - give more than needed
        deal(address(investmentToken), deployer, DEPOSIT_AMOUNT * 2);
        console.log("Minted tokens for deployer. New balance:", investmentToken.balanceOf(deployer));
        
        // Approve and make direct deposit
        vm.startPrank(deployer);
        investmentToken.approve(stoAddress, DEPOSIT_AMOUNT);
        console.log("Approved STO to spend tokens");
        
        try sto.buyTokens(deployer, DEPOSIT_AMOUNT) {
            console.log("Successfully deposited", DEPOSIT_AMOUNT, "tokens");
            
            // Verify deposit was successful
            try escrow.getInvestment(deployer) returns (uint256 newInvestment) {
                console.log("New investment in escrow:", newInvestment);
                assertGt(newInvestment, initialInvestment, "Investment should increase after deposit");
            } catch {
                console.log("Failed to get updated investment");
            }
        } catch Error(string memory reason) {
            console.log("Deposit failed:", reason);
            assertTrue(false, string.concat("Deposit failed: ", reason));
        } catch (bytes memory revertData) {
            console.log("Deposit failed with raw error:");
            console.logBytes(revertData);
            assertTrue(false, "Deposit failed with raw error");
        }
        
        vm.stopPrank();
    }
    
    /**
     * @notice Test a partial withdrawal (withdrawing less than the deposit)
     */
    function testPartialWithdrawal() public {
        console.log("\n=== TESTING PARTIAL WITHDRAWAL ===");
        console.log("Withdrawal amount:", WITHDRAWAL_SMALL, "(less than deposit)");
        
        // Skip test if STO is closed
        (,,,,,,,,,, bool stoClosed) = sto.getSTODetails();
        if (stoClosed) {
            console.log("STO is closed, skipping test");
            return;
        }
        
        // Check if escrow is finalized
        bool escrowFinalized = escrow.isFinalized();
        if (escrowFinalized) {
            console.log("Escrow is finalized, skipping test");
            return;
        }
        
        // Step 1: Check if deployer has enough investment in the STO
        uint256 investmentAmount = 0;
        try escrow.getInvestment(deployer) returns (uint256 investment) {
            investmentAmount = investment;
            console.log("Deployer investment in escrow:", investmentAmount);
            assertGe(investmentAmount, WITHDRAWAL_SMALL, "Investment should be enough for partial withdrawal");
        } catch Error(string memory reason) {
            console.log("Failed to get deployer investment:", reason);
            assertTrue(false, string.concat("Failed to get deployer investment: ", reason));
            return;
        } catch {
            console.log("Failed to get deployer investment (unknown error)");
            assertTrue(false, "Failed to get deployer investment (unknown error)");
            return;
        }
        
        // Step 2: Get current nonce for the deployer from InvestmentManager
        uint256 nonce = investmentManager.getNonce(deployer);
        console.log("Current deployer nonce in InvestmentManager:", nonce);
        
        // Step 3: Create the withdrawal request
        Withdrawal.WithdrawalInfo memory withdrawal = Withdrawal.WithdrawalInfo({
            investor: deployer,
            investmentToken: investmentTokenAddress,
            withdrawalAmount: WITHDRAWAL_SMALL,
            nonce: nonce
        });
        
        console.log("Created withdrawal request:");
        console.log("- Investor:", withdrawal.investor);
        console.log("- Investment Token:", withdrawal.investmentToken);
        console.log("- Withdrawal Amount:", withdrawal.withdrawalAmount);
        console.log("- Nonce:", withdrawal.nonce);
        
        // Step 4: Get domain separator from the Signatures contract
        bytes32 domainSeparator = signatures.getDomainSeparator();
        console.log("Domain Separator:", vm.toString(domainSeparator));
        
        // Step 5: Hash the withdrawal with typed data according to EIP-712
        bytes32 withdrawalHash = keccak256(abi.encode(
            Withdrawal.WITHDRAWAL_TYPEHASH,
            withdrawal.investor,
            withdrawal.investmentToken,
            withdrawal.withdrawalAmount,
            withdrawal.nonce
        ));
        
        // Calculate the complete digest hash (EIP-712 format)
        bytes32 digestHash = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            withdrawalHash
        ));
        console.log("Digest hash:", vm.toString(digestHash));
        
        // Step 6: Sign the digestHash using the deployer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, digestHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        console.log("Signature created with length:", signature.length);
        
        // Record initial balances
        uint256 escrowBalanceBefore = investmentToken.balanceOf(address(escrow));
        uint256 deployerBalanceBefore = investmentToken.balanceOf(deployer);
        console.log("Escrow balance before withdrawal:", escrowBalanceBefore);
        console.log("Deployer balance before withdrawal:", deployerBalanceBefore);
        
        // Step 7: Submit the signed withdrawal
        vm.startPrank(deployer);
        console.log("Submitting signed withdrawal...");
        
        try sto.executeSignedWithdrawal(withdrawal, signature) {
            console.log("Withdrawal execution successful");
            
            // Step 8: Verify withdrawal was processed correctly
            (,,,,uint256 fundsRaisedAfter,,,,,, ) = sto.getSTODetails();
            
            // Verify balances changed correctly
            uint256 deployerBalanceAfter = investmentToken.balanceOf(deployer);
            uint256 escrowBalanceAfter = investmentToken.balanceOf(address(escrow));
            
            console.log("Deployer balance after withdrawal:", deployerBalanceAfter);
            console.log("Deployer balance increased by:", deployerBalanceAfter - deployerBalanceBefore);
            console.log("Escrow balance after withdrawal:", escrowBalanceAfter);
            console.log("Escrow balance decreased by:", escrowBalanceBefore - escrowBalanceAfter);
            
            // Verify amounts match expected values
            assertEq(deployerBalanceAfter - deployerBalanceBefore, WITHDRAWAL_SMALL, 
                "Deployer balance should increase by withdrawal amount");
            assertEq(escrowBalanceBefore - escrowBalanceAfter, WITHDRAWAL_SMALL, 
                "Escrow balance should decrease by withdrawal amount");
            
            // Check updated investment
            uint256 investmentAfter = escrow.getInvestment(deployer);
            console.log("Deployer investment after withdrawal:", investmentAfter);
            console.log("Investment decreased by:", investmentAmount - investmentAfter);
            assertEq(investmentAfter, investmentAmount - WITHDRAWAL_SMALL, 
                "Investment should decrease by withdrawal amount");
            
            // Verify there's still investment left
            assertGt(investmentAfter, 0, "There should still be investment remaining");
            
            // Verify nonce was incremented
            uint256 newNonce = investmentManager.getNonce(deployer);
            console.log("New deployer nonce:", newNonce);
            assertEq(newNonce, nonce + 1, "Nonce should be incremented after withdrawal execution");
            
        } catch Error(string memory reason) {
            console.log("Withdrawal execution failed:", reason);
            assertTrue(false, string.concat("Withdrawal execution failed: ", reason));
        } catch (bytes memory revertData) {
            console.log("Withdrawal execution failed with raw error:");
            console.logBytes(revertData);
            assertTrue(false, "Withdrawal execution failed with raw error");
        }
        
        vm.stopPrank();
    }
    
    /**
     * @notice Test withdrawing the exact deposit amount
     */
    function testExactWithdrawal() public {
        console.log("\n=== TESTING EXACT WITHDRAWAL ===");
        console.log("Withdrawal amount:", WITHDRAWAL_EXACT, "(equal to deposit)");
        
        // Skip test if STO is closed
        (,,,,,,,,,, bool stoClosed) = sto.getSTODetails();
        if (stoClosed) {
            console.log("STO is closed, skipping test");
            return;
        }
        
        // Check if escrow is finalized
        bool escrowFinalized = escrow.isFinalized();
        if (escrowFinalized) {
            console.log("Escrow is finalized, skipping test");
            return;
        }
        
        // Step 1: Check if deployer has enough investment in the STO
        uint256 investmentAmount = 0;
        try escrow.getInvestment(deployer) returns (uint256 investment) {
            investmentAmount = investment;
            console.log("Deployer investment in escrow:", investmentAmount);
            
            if (investmentAmount < WITHDRAWAL_EXACT) {
                console.log("Investment not enough for exact withdrawal test, making additional deposit");
                
                // If we need to add more funds, make another deposit first
                uint256 additionalAmount = WITHDRAWAL_EXACT - investmentAmount;
                deal(address(investmentToken), deployer, additionalAmount * 2);
                
                vm.startPrank(deployer);
                investmentToken.approve(stoAddress, additionalAmount);
                sto.buyTokens(deployer, additionalAmount);
                vm.stopPrank();
                
                // Check updated investment
                investmentAmount = escrow.getInvestment(deployer);
                console.log("Updated investment after additional deposit:", investmentAmount);
            }
            
            assertGe(investmentAmount, WITHDRAWAL_EXACT, "Investment should be enough for exact withdrawal");
        } catch Error(string memory reason) {
            console.log("Failed to get deployer investment:", reason);
            assertTrue(false, string.concat("Failed to get deployer investment: ", reason));
            return;
        } catch {
            console.log("Failed to get deployer investment (unknown error)");
            assertTrue(false, "Failed to get deployer investment (unknown error)");
            return;
        }
        
        // Step 2: Get current nonce for the deployer from InvestmentManager
        uint256 nonce = investmentManager.getNonce(deployer);
        console.log("Current deployer nonce in InvestmentManager:", nonce);
        
        // Step 3: Create the withdrawal request
        Withdrawal.WithdrawalInfo memory withdrawal = Withdrawal.WithdrawalInfo({
            investor: deployer,
            investmentToken: investmentTokenAddress,
            withdrawalAmount: WITHDRAWAL_EXACT,
            nonce: nonce
        });
        
        console.log("Created withdrawal request:");
        console.log("- Investor:", withdrawal.investor);
        console.log("- Investment Token:", withdrawal.investmentToken);
        console.log("- Withdrawal Amount:", withdrawal.withdrawalAmount);
        console.log("- Nonce:", withdrawal.nonce);
        
        // Step 4: Get domain separator from the Signatures contract
        bytes32 domainSeparator = signatures.getDomainSeparator();
        
        // Step 5: Hash the withdrawal with typed data according to EIP-712
        bytes32 withdrawalHash = keccak256(abi.encode(
            Withdrawal.WITHDRAWAL_TYPEHASH,
            withdrawal.investor,
            withdrawal.investmentToken,
            withdrawal.withdrawalAmount,
            withdrawal.nonce
        ));
        
        // Calculate the complete digest hash (EIP-712 format)
        bytes32 digestHash = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            withdrawalHash
        ));
        
        // Step 6: Sign the digestHash using the deployer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, digestHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Record initial balances
        uint256 escrowBalanceBefore = investmentToken.balanceOf(address(escrow));
        uint256 deployerBalanceBefore = investmentToken.balanceOf(deployer);
        console.log("Escrow balance before withdrawal:", escrowBalanceBefore);
        console.log("Deployer balance before withdrawal:", deployerBalanceBefore);
        
        // Step 7: Submit the signed withdrawal
        vm.startPrank(deployer);
        console.log("Submitting signed withdrawal...");
        
        try sto.executeSignedWithdrawal(withdrawal, signature) {
            console.log("Withdrawal execution successful");
            
            // Step 8: Verify withdrawal was processed correctly
            uint256 deployerBalanceAfter = investmentToken.balanceOf(deployer);
            uint256 escrowBalanceAfter = investmentToken.balanceOf(address(escrow));
            
            console.log("Deployer balance after withdrawal:", deployerBalanceAfter);
            console.log("Deployer balance increased by:", deployerBalanceAfter - deployerBalanceBefore);
            console.log("Escrow balance after withdrawal:", escrowBalanceAfter);
            console.log("Escrow balance decreased by:", escrowBalanceBefore - escrowBalanceAfter);
            
            // Verify amounts match expected values
            assertEq(deployerBalanceAfter - deployerBalanceBefore, WITHDRAWAL_EXACT, 
                "Deployer balance should increase by withdrawal amount");
            assertEq(escrowBalanceBefore - escrowBalanceAfter, WITHDRAWAL_EXACT, 
                "Escrow balance should decrease by withdrawal amount");
            
            // Check updated investment
            try escrow.getInvestment(deployer) returns (uint256 investmentAfter) {
                console.log("Deployer investment after withdrawal:", investmentAfter);
                console.log("Investment decreased by:", investmentAmount - investmentAfter);
                
                // Since we withdrew exactly the investment amount, the remaining should be 0 or very close to 0
                assertLe(investmentAfter, 100, "Investment should be fully withdrawn (or very small remainder)");
            } catch {
                // If the investment record is deleted after full withdrawal, this might fail
                console.log("No investment record found after withdrawal (expected for full withdrawal)");
            }
            
            // Verify nonce was incremented
            uint256 newNonce = investmentManager.getNonce(deployer);
            console.log("New deployer nonce:", newNonce);
            assertEq(newNonce, nonce + 1, "Nonce should be incremented after withdrawal execution");
            
        } catch Error(string memory reason) {
            console.log("Withdrawal execution failed:", reason);
            assertTrue(false, string.concat("Withdrawal execution failed: ", reason));
        } catch (bytes memory revertData) {
            console.log("Withdrawal execution failed with raw error:");
            console.logBytes(revertData);
            assertTrue(false, "Withdrawal execution failed with raw error");
        }
        
        vm.stopPrank();
    }
    
    /**
     * @notice Test withdrawing more than the deposit amount (should fail)
     */
    function testExcessWithdrawal() public {
        console.log("\n=== TESTING EXCESS WITHDRAWAL ===");
        console.log("Withdrawal amount:", WITHDRAWAL_EXCESS, "(more than deposit)");
        
        // Skip test if STO is closed
        (,,,,,,,,,, bool stoClosed) = sto.getSTODetails();
        if (stoClosed) {
            console.log("STO is closed, skipping test");
            return;
        }
        
        // Check if escrow is finalized
        bool escrowFinalized = escrow.isFinalized();
        if (escrowFinalized) {
            console.log("Escrow is finalized, skipping test");
            return;
        }
        
        // Step 1: Check current investment amount
        uint256 investmentAmount = 0;
        try escrow.getInvestment(deployer) returns (uint256 investment) {
            investmentAmount = investment;
            console.log("Deployer investment in escrow:", investmentAmount);
            
            // Ensure the withdrawal amount is actually larger than investment
            assertLt(investmentAmount, WITHDRAWAL_EXCESS, "Investment should be less than requested withdrawal");
        } catch Error(string memory reason) {
            console.log("Failed to get deployer investment:", reason);
            return;
        } catch {
            console.log("Failed to get deployer investment (unknown error)");
            return;
        }
        
        // Step 2: Get current nonce for the deployer from InvestmentManager
        uint256 nonce = investmentManager.getNonce(deployer);
        console.log("Current deployer nonce in InvestmentManager:", nonce);
        
        // Step 3: Create the withdrawal request for excess amount
        Withdrawal.WithdrawalInfo memory withdrawal = Withdrawal.WithdrawalInfo({
            investor: deployer,
            investmentToken: investmentTokenAddress,
            withdrawalAmount: WITHDRAWAL_EXCESS,
            nonce: nonce
        });
        
        console.log("Created withdrawal request:");
        console.log("- Investor:", withdrawal.investor);
        console.log("- Investment Token:", withdrawal.investmentToken);
        console.log("- Withdrawal Amount:", withdrawal.withdrawalAmount);
        console.log("- Nonce:", withdrawal.nonce);
        
        // Step 4: Get domain separator from the Signatures contract
        bytes32 domainSeparator = signatures.getDomainSeparator();
        
        // Step 5: Hash the withdrawal with typed data according to EIP-712
        bytes32 withdrawalHash = keccak256(abi.encode(
            Withdrawal.WITHDRAWAL_TYPEHASH,
            withdrawal.investor,
            withdrawal.investmentToken,
            withdrawal.withdrawalAmount,
            withdrawal.nonce
        ));
        
        // Calculate the complete digest hash (EIP-712 format)
        bytes32 digestHash = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            withdrawalHash
        ));
        
        // Step 6: Sign the digestHash using the deployer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, digestHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Record initial balances
        uint256 escrowBalanceBefore = investmentToken.balanceOf(address(escrow));
        uint256 deployerBalanceBefore = investmentToken.balanceOf(deployer);
        console.log("Escrow balance before withdrawal:", escrowBalanceBefore);
        console.log("Deployer balance before withdrawal:", deployerBalanceBefore);
        
        // Step 7: Submit the signed withdrawal (should fail)
        vm.startPrank(deployer);
        console.log("Submitting signed withdrawal (expecting failure)...");
        
        // The transaction should revert
        vm.expectRevert();
        sto.executeSignedWithdrawal(withdrawal, signature);
        
        console.log("Transaction reverted as expected");
        
        // Verify nothing changed
        uint256 deployerBalanceAfter = investmentToken.balanceOf(deployer);
        uint256 escrowBalanceAfter = investmentToken.balanceOf(address(escrow));
        
        console.log("Deployer balance after failed withdrawal:", deployerBalanceAfter);
        console.log("Escrow balance after failed withdrawal:", escrowBalanceAfter);
        
        // Verify balances remained the same
        assertEq(deployerBalanceAfter, deployerBalanceBefore, "Deployer balance should not change");
        assertEq(escrowBalanceAfter, escrowBalanceBefore, "Escrow balance should not change");
        
        // Verify investment amount remained the same
        try escrow.getInvestment(deployer) returns (uint256 investmentAfter) {
            console.log("Deployer investment after failed withdrawal:", investmentAfter);
            assertEq(investmentAfter, investmentAmount, "Investment should not change after failed withdrawal");
        } catch {
            assertTrue(false, "Investment record should still exist");
        }
        
        // Verify nonce was not incremented
        uint256 newNonce = investmentManager.getNonce(deployer);
        console.log("Deployer nonce after failed withdrawal:", newNonce);
        assertEq(newNonce, nonce, "Nonce should not increment after failed withdrawal");
        
        vm.stopPrank();
        
        console.log("Excess withdrawal test passed: withdrawal was properly rejected");
    }
}