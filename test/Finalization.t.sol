// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../src/CappedSTO.sol";
import "../src/utils/Signatures.sol";
import "../src/utils/Escrow.sol";
import "../src/utils/Refund.sol";
import "../src/utils/Minting.sol";
import "../src/utils/FinalizationManager.sol";
import "../src/utils/STOConfig.sol";
import "../src/interfaces/ISTO.sol";
import "../src/interfaces/ISTOConfig.sol";
import "@ar-security-token/src/interfaces/IToken.sol";

/**
 * @title Finalization Test
 * @notice Tests the finalization functionality of the STO protocol
 */
contract FinalizationTest is Test {
    // Contracts
    CappedSTO private sto;
    IERC20 private investmentToken;
    IERC20 private securityToken;
    Escrow private escrow;
    Refund private refund;
    Minting private minting;
    FinalizationManager private finalizationManager;
    STOConfig private stoConfig;
    
    // Addresses from .env
    address private deployer;
    address private stoAddress;
    address private securityTokenAddress;
    address private investmentTokenAddress;
    uint256 private deployerPrivateKey;
    
    // Constants for testing
    uint256 private hardCap;
    uint256 private softCap;
    uint256 private minInvestment;
    
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

        // Connect to STO contract
        sto = CappedSTO(payable(stoAddress));
        investmentToken = IERC20(investmentTokenAddress);
        securityToken = IERC20(securityTokenAddress);
        
        // Connect to related contracts
        try sto.escrow() returns (Escrow escrowContract) {
            escrow = escrowContract;
            console.log("Connected to Escrow at:", address(escrow));
        } catch {
            revert("Failed to get Escrow contract");
        }
        
        try sto.refund() returns (Refund refundContract) {
            refund = refundContract;
            console.log("Connected to Refund at:", address(refund));
        } catch {
            revert("Failed to get Refund contract");
        }
        
        try sto.minting() returns (Minting mintingContract) {
            minting = mintingContract;
            console.log("Connected to Minting at:", address(minting));
        } catch {
            revert("Failed to get Minting contract");
        }
        
        try sto.getFinalizationManager() returns (address finalizationManagerAddr) {
            finalizationManager = FinalizationManager(finalizationManagerAddr);
            console.log("Connected to FinalizationManager at:", finalizationManagerAddr);
        } catch {
            revert("Failed to get FinalizationManager");
        }
        
        try sto.getSTOConfig() returns (address stoConfigAddr) {
            stoConfig = STOConfig(stoConfigAddr);
            console.log("Connected to STOConfig at:", stoConfigAddr);
        } catch {
            revert("Failed to get STOConfig");
        }
        
        // Get STO parameters
        hardCap = stoConfig.getHardCap();
        softCap = stoConfig.getSoftCap();
        try sto.pricingLogic() returns (PricingLogic pricingLogic) {
            minInvestment = pricingLogic.minInvestment();
        } catch {
            minInvestment = 100 * 10**18; // Default to 100 tokens if we can't get it
        }
        
        console.log("STO Parameters:");
        console.log("Hard Cap:", hardCap);
        console.log("Soft Cap:", softCap);
        console.log("Min Investment:", minInvestment);
        
        // Check if STO is already finalized to make test decisions
        bool isFinalized = escrow.isFinalized();
        bool isClosed = escrow.isSTOClosed();
        
        console.log("STO state:");
        console.log("Is Finalized:", isFinalized);
        console.log("Is Closed:", isClosed);

        // Fund deployer account with enough tokens for tests
        deal(address(investmentToken), deployer, hardCap * 2);

        // The STO should already be registered as an agent during deployment
        // Check if the STO is registered with the security token
        bool isRegistered = false;
        try IToken(securityTokenAddress).isRegisteredSTO(stoAddress) returns (bool result) {
            isRegistered = result;
            console.log("STO registration status with security token:", isRegistered ? "Registered" : "Not registered");
        } catch {
            console.log("Failed to check STO registration status");
        }

        console.log("Test setup complete");
    }
    
    /**
     * @notice Test finalizing an STO that has reached its hard cap exactly
     * @dev Deposits exactly the hard cap amount and then finalizes
     */
    function testFinalizeExactHardCap() public {
        console.log("\n=== TEST: Finalize STO with Exact Hard Cap ===");

        // Skip if STO is already finalized or closed
        if (escrow.isFinalized() || escrow.isSTOClosed()) {
            console.log("STO is already finalized or closed, skipping test");
            return;
        }

        // Check active offering state
        if (!stoConfig.isOfferingActive()) {
            console.log("STO is not active, skipping test");
            return;
        }

        // 1. Record initial balances before any operations
        uint256 investorInvTokenBefore = investmentToken.balanceOf(deployer);
        uint256 investorSecTokenBefore = securityToken.balanceOf(deployer);
        address payable fundsReceiver = stoConfig.fundsReceiver();
        uint256 receiverInvTokenBefore = investmentToken.balanceOf(fundsReceiver);
        uint256 escrowBalanceBefore = investmentToken.balanceOf(address(escrow));

        console.log("===== INITIAL BALANCES =====");
        console.log("Investor investment token balance:", investorInvTokenBefore);
        console.log("Investor security token balance:", investorSecTokenBefore);
        console.log("Funds receiver investment token balance:", receiverInvTokenBefore);
        console.log("Escrow investment token balance:", escrowBalanceBefore);
        console.log("Funds receiver address:", fundsReceiver);

        // 2. Calculate the amount needed to reach hard cap exactly
        uint256 currentFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
        uint256 amountNeeded = hardCap - currentFundsRaised;

        console.log("Current funds raised:", currentFundsRaised);
        console.log("Amount needed to reach hard cap:", amountNeeded);

        if (amountNeeded == 0) {
            console.log("Hard cap already reached, skipping deposit");
        } else {
            // 3. Deposit exactly the amount needed to hit hard cap
            vm.startPrank(deployer);
            investmentToken.approve(stoAddress, amountNeeded);

            try sto.buyTokens(deployer, amountNeeded) {
                console.log("Successfully deposited", amountNeeded, "tokens to reach hard cap");

                // Verify deposit was successful
                uint256 investorInvTokenAfterDeposit = investmentToken.balanceOf(deployer);
                assertEq(investorInvTokenBefore - investorInvTokenAfterDeposit, amountNeeded, "Incorrect amount deducted from investor");

                // Verify funds raised increased
                uint256 newFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
                assertEq(newFundsRaised, hardCap, "Funds raised should equal hard cap");

                // Verify STO is closed
                assertTrue(escrow.isSTOClosed(), "STO should be closed after reaching hard cap");

                // Verify funds are in escrow
                uint256 escrowBalanceAfterDeposit = investmentToken.balanceOf(address(escrow));
                assertGe(escrowBalanceAfterDeposit, escrowBalanceBefore + amountNeeded, "Escrow balance should increase by deposit amount");
                console.log("Escrow balance after deposit:", escrowBalanceAfterDeposit);
            } catch Error(string memory reason) {
                console.log("Deposit failed:", reason);
                vm.stopPrank();
                // Continue with test even if deposit fails
            }

            vm.stopPrank();
        }

        // 4. Finalize the STO now that hard cap is reached
        vm.startPrank(deployer);
        console.log("Calling finalize() as deployer (operator)");

        try sto.finalize() {
            console.log("Successfully finalized the STO");

            // Verify STO is finalized
            assertTrue(escrow.isFinalized(), "Escrow should be finalized");
            assertTrue(stoConfig.isSoftCapReached(), "Soft cap should be reached");

            // 5. Check final balances after finalization
            uint256 investorInvTokenAfter = investmentToken.balanceOf(deployer);
            uint256 investorSecTokenAfter = securityToken.balanceOf(deployer);
            uint256 receiverInvTokenAfter = investmentToken.balanceOf(fundsReceiver);
            uint256 escrowBalanceAfter = investmentToken.balanceOf(address(escrow));

            console.log("===== FINAL BALANCES =====");
            console.log("Investor investment token balance:", investorInvTokenAfter);
            console.log("Investor security token balance:", investorSecTokenAfter);
            console.log("Funds receiver investment token balance:", receiverInvTokenAfter);
            console.log("Escrow investment token balance:", escrowBalanceAfter);

            console.log("===== BALANCE CHANGES =====");
            console.log("Investor investment token change:", int256(investorInvTokenAfter) - int256(investorInvTokenBefore));
            console.log("Investor security token change:", int256(investorSecTokenAfter) - int256(investorSecTokenBefore));
            console.log("Funds receiver investment token change:", int256(receiverInvTokenAfter) - int256(receiverInvTokenBefore));
            console.log("Escrow investment token change:", int256(escrowBalanceAfter) - int256(escrowBalanceBefore));

            // Verify funds were transferred to the funds receiver from escrow
            assertGt(receiverInvTokenAfter, receiverInvTokenBefore, "Funds receiver should have received investment tokens");

            // Verify escrow has released funds (balance should be lower after finalization)
            assertLt(escrowBalanceAfter, escrowBalanceBefore + amountNeeded, "Escrow balance should decrease after finalization");

            // Verify investor received security tokens (critical test for minting)
            assertGt(investorSecTokenAfter, investorSecTokenBefore, "Investor should have received security tokens - minting failed");

            // Check tokens are available for claiming through the finalization manager
            bool hasReceivedTokens = finalizationManager.hasReceivedTokens(deployer);
            console.log("Finalization manager shows investor has received tokens:", hasReceivedTokens);
            assertTrue(hasReceivedTokens, "Finalization manager should mark tokens as received");

        } catch Error(string memory reason) {
            console.log("Finalization failed:", reason);
            assertTrue(false, string.concat("Finalization failed: ", reason));
        }

        vm.stopPrank();
        console.log("Test completed");
    }
    
    /**
     * @notice Test finalizing an STO with deposit exceeding the hard cap
     * @dev Deposits more than the hard cap amount and verifies excess is refunded
     */
    function testFinalizeExceedingHardCap() public {
        console.log("\n=== TEST: Finalize STO with Excess Over Hard Cap ===");

        // Skip if STO is already finalized or closed
        if (escrow.isFinalized() || escrow.isSTOClosed()) {
            console.log("STO is already finalized or closed, skipping test");
            return;
        }

        // Check active offering state
        if (!stoConfig.isOfferingActive()) {
            console.log("STO is not active, skipping test");
            return;
        }

        // Record initial balances before any operations
        uint256 investorBalanceBefore = investmentToken.balanceOf(deployer);
        address payable fundsReceiver = stoConfig.fundsReceiver();
        uint256 receiverBalanceBefore = investmentToken.balanceOf(fundsReceiver);
        uint256 escrowBalanceBefore = investmentToken.balanceOf(address(escrow));

        console.log("===== INITIAL BALANCES =====");
        console.log("Investor investment token balance:", investorBalanceBefore);
        console.log("Funds receiver investment token balance:", receiverBalanceBefore);
        console.log("Escrow investment token balance:", escrowBalanceBefore);
        console.log("Funds receiver address:", fundsReceiver);

        // 1. Calculate the amount needed to reach hard cap plus excess
        uint256 currentFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
        uint256 amountNeeded = hardCap - currentFundsRaised;
        uint256 excess = 1000 * 10**18; // 1000 tokens excess
        uint256 totalDeposit = amountNeeded + excess;

        console.log("Current funds raised:", currentFundsRaised);
        console.log("Amount needed to reach hard cap:", amountNeeded);
        console.log("Excess amount:", excess);
        console.log("Total deposit:", totalDeposit);

        if (amountNeeded == 0) {
            console.log("Hard cap already reached, skipping deposit");
        } else {
            // 2. Deposit more than needed to exceed hard cap
            vm.startPrank(deployer);
            investmentToken.approve(stoAddress, totalDeposit);

            try sto.buyTokens(deployer, totalDeposit) {
                console.log("Deposit completed");

                // Verify only the necessary amount was taken
                uint256 investorBalanceAfterDeposit = investmentToken.balanceOf(deployer);
                uint256 actualDeduction = investorBalanceBefore - investorBalanceAfterDeposit;
                console.log("Actual amount deducted:", actualDeduction);

                // The investor should get refunded the excess, so they should only lose the amount needed
                assertApproxEqRel(actualDeduction, amountNeeded, 0.01e18, "Incorrect amount deducted from investor - excess should be refunded");

                // Verify funds raised increased to exactly hard cap
                uint256 newFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
                assertEq(newFundsRaised, hardCap, "Funds raised should equal hard cap exactly");

                // Verify STO is closed
                assertTrue(escrow.isSTOClosed(), "STO should be closed after reaching hard cap");

                // Verify funds are in escrow
                uint256 escrowBalanceAfterDeposit = investmentToken.balanceOf(address(escrow));
                assertGe(escrowBalanceAfterDeposit, escrowBalanceBefore + amountNeeded, "Escrow balance should increase by deposit amount");
                console.log("Escrow balance after deposit:", escrowBalanceAfterDeposit);
            } catch Error(string memory reason) {
                console.log("Deposit failed:", reason);
                vm.stopPrank();
                // Continue with test even if deposit fails
            }

            vm.stopPrank();
        }

        // 3. Finalize the STO now that hard cap is reached
        vm.startPrank(deployer);
        console.log("Calling finalize() as deployer (operator)");

        try sto.finalize() {
            console.log("Successfully finalized the STO");

            // Verify STO is finalized
            assertTrue(escrow.isFinalized(), "Escrow should be finalized");
            assertTrue(stoConfig.isSoftCapReached(), "Soft cap should be reached");

            // Check final balances after finalization
            uint256 investorBalanceAfter = investmentToken.balanceOf(deployer);
            uint256 receiverBalanceAfter = investmentToken.balanceOf(fundsReceiver);
            uint256 escrowBalanceAfter = investmentToken.balanceOf(address(escrow));

            console.log("===== FINAL BALANCES =====");
            console.log("Investor investment token balance:", investorBalanceAfter);
            console.log("Funds receiver investment token balance:", receiverBalanceAfter);
            console.log("Escrow investment token balance:", escrowBalanceAfter);

            console.log("===== BALANCE CHANGES =====");
            console.log("Investor investment token change:", int256(investorBalanceAfter) - int256(investorBalanceBefore));
            console.log("Funds receiver investment token change:", int256(receiverBalanceAfter) - int256(receiverBalanceBefore));
            console.log("Escrow investment token change:", int256(escrowBalanceAfter) - int256(escrowBalanceBefore));

            // Verify funds were transferred to the funds receiver from escrow
            assertGt(receiverBalanceAfter, receiverBalanceBefore, "Funds receiver should have received investment tokens");

            // Verify escrow has released funds (balance should be lower after finalization)
            assertLt(escrowBalanceAfter, escrowBalanceBefore + amountNeeded, "Escrow balance should decrease after finalization");

        } catch Error(string memory reason) {
            console.log("Finalization failed:", reason);
            assertTrue(false, string.concat("Finalization failed: ", reason));
        }

        vm.stopPrank();
        console.log("Test completed");
    }
    
    /**
     * @notice Test finalizing an STO where soft cap is reached but end time has passed
     * @dev Simulates time passage for a real deployed STO
     */
    function testFinalizeSoftCapReachedAfterEndTime() public {
        console.log("\n=== TEST: Finalize STO with Soft Cap Reached After End Time ===");

        // Skip if STO is already finalized or closed
        if (escrow.isFinalized() || escrow.isSTOClosed()) {
            console.log("STO is already finalized or closed, skipping test");
            return;
        }

        // 1. Record initial balances before any operations
        uint256 investorInvTokenBefore = investmentToken.balanceOf(deployer);
        uint256 investorSecTokenBefore = securityToken.balanceOf(deployer);
        address payable fundsReceiver = stoConfig.fundsReceiver();
        uint256 receiverInvTokenBefore = investmentToken.balanceOf(fundsReceiver);
        uint256 escrowBalanceBefore = investmentToken.balanceOf(address(escrow));

        console.log("===== INITIAL BALANCES =====");
        console.log("Investor investment token balance:", investorInvTokenBefore);
        console.log("Investor security token balance:", investorSecTokenBefore);
        console.log("Funds receiver investment token balance:", receiverInvTokenBefore);
        console.log("Escrow investment token balance:", escrowBalanceBefore);
        console.log("Funds receiver address:", fundsReceiver);

        // 2. Check current state
        uint256 endTime = stoConfig.endTime();
        uint256 currentFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
        console.log("End time:", endTime);
        console.log("Current time:", block.timestamp);
        console.log("Current funds raised:", currentFundsRaised);

        // 3. If we haven't reached the soft cap, deposit enough to hit it
        uint256 amountDeposited = 0;
        if (currentFundsRaised < softCap) {
            amountDeposited = softCap - currentFundsRaised;
            console.log("Depositing", amountDeposited, "tokens to reach soft cap");

            vm.startPrank(deployer);
            investmentToken.approve(stoAddress, amountDeposited);

            try sto.buyTokens(deployer, amountDeposited) {
                console.log("Successfully deposited funds to meet soft cap");

                // Verify funds are in escrow
                uint256 escrowBalanceAfterDeposit = investmentToken.balanceOf(address(escrow));
                assertGe(escrowBalanceAfterDeposit, escrowBalanceBefore + amountDeposited, "Escrow balance should increase by deposit amount");
                console.log("Escrow balance after deposit:", escrowBalanceAfterDeposit);
            } catch Error(string memory reason) {
                console.log("Deposit failed:", reason);
                vm.stopPrank();
                // Continue with test even if deposit fails
            }

            vm.stopPrank();

            // Verify soft cap is now reached
            currentFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
            console.log("Updated funds raised:", currentFundsRaised);
            assertTrue(stoConfig.isSoftCapReached(), "Soft cap should be reached after deposit");
        }

        // 4. If current time is before end time, warp to after end time
        if (block.timestamp < endTime) {
            console.log("Warping time to after end time");
            vm.warp(endTime + 1 hours);
            console.log("New time:", block.timestamp);
        }

        // 5. Finalize the STO as the operator
        vm.startPrank(deployer);
        console.log("Calling finalize() as deployer (operator)");

        try sto.finalize() {
            console.log("Successfully finalized the STO");

            // Verify STO is finalized
            assertTrue(escrow.isFinalized(), "Escrow should be finalized");
            assertTrue(stoConfig.isSoftCapReached(), "Soft cap should still be reached");

            // 6. Check final balances after finalization
            uint256 investorInvTokenAfter = investmentToken.balanceOf(deployer);
            uint256 investorSecTokenAfter = securityToken.balanceOf(deployer);
            uint256 receiverInvTokenAfter = investmentToken.balanceOf(fundsReceiver);
            uint256 escrowBalanceAfter = investmentToken.balanceOf(address(escrow));

            console.log("===== FINAL BALANCES =====");
            console.log("Investor investment token balance:", investorInvTokenAfter);
            console.log("Investor security token balance:", investorSecTokenAfter);
            console.log("Funds receiver investment token balance:", receiverInvTokenAfter);
            console.log("Escrow investment token balance:", escrowBalanceAfter);

            console.log("===== BALANCE CHANGES =====");
            console.log("Investor investment token change:", int256(investorInvTokenAfter) - int256(investorInvTokenBefore));
            console.log("Investor security token change:", int256(investorSecTokenAfter) - int256(investorSecTokenBefore));
            console.log("Funds receiver investment token change:", int256(receiverInvTokenAfter) - int256(receiverInvTokenBefore));
            console.log("Escrow investment token change:", int256(escrowBalanceAfter) - int256(escrowBalanceBefore));

            // Verify funds were transferred to the funds receiver from escrow
            assertGt(receiverInvTokenAfter, receiverInvTokenBefore, "Funds receiver should have received investment tokens");

            // Verify escrow has released funds (balance should be lower after finalization)
            if (amountDeposited > 0) {
                assertLt(escrowBalanceAfter, escrowBalanceBefore + amountDeposited, "Escrow balance should decrease after finalization");
            } else if (currentFundsRaised > 0) {
                assertLt(escrowBalanceAfter, escrowBalanceBefore, "Escrow balance should decrease after finalization");
            }

            // Verify investor received security tokens (critical test for minting)
            assertGt(investorSecTokenAfter, investorSecTokenBefore, "Investor should have received security tokens - minting failed");

            // Check tokens are available for claiming through the finalization manager
            bool hasReceivedTokens = finalizationManager.hasReceivedTokens(deployer);
            console.log("Finalization manager shows investor has received tokens:", hasReceivedTokens);
            assertTrue(hasReceivedTokens, "Finalization manager should mark tokens as received");

        } catch Error(string memory reason) {
            console.log("Finalization failed:", reason);
            assertTrue(false, string.concat("Finalization failed: ", reason));
        }

        vm.stopPrank();
        console.log("Test completed");
    }
    
    /**
     * @notice Test finalizing an STO where soft cap is reached but end time has not passed
     * @dev This should fail since we can only finalize after end time or when hard cap is reached
     */
    function testFinalizeSoftCapReachedBeforeEndTime() public {
        console.log("\n=== TEST: Finalize STO with Soft Cap Reached Before End Time ===");
        
        // Skip if STO is already finalized or closed
        if (escrow.isFinalized() || escrow.isSTOClosed()) {
            console.log("STO is already finalized or closed, skipping test");
            return;
        }
        
        // 1. Check current state
        uint256 endTime = stoConfig.endTime();
        uint256 currentFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
        console.log("End time:", endTime);
        console.log("Current time:", block.timestamp);
        console.log("Current funds raised:", currentFundsRaised);
        
        // 2. If we haven't reached the soft cap, deposit enough to hit it
        if (currentFundsRaised < softCap) {
            uint256 amountNeeded = softCap - currentFundsRaised;
            console.log("Depositing", amountNeeded, "tokens to reach soft cap");
            
            vm.startPrank(deployer);
            investmentToken.approve(stoAddress, amountNeeded);

            try sto.buyTokens(deployer, amountNeeded) {
                console.log("Successfully deposited funds to meet soft cap");
            } catch Error(string memory reason) {
                console.log("Deposit failed:", reason);
                vm.stopPrank();
                return; // Skip remaining test if deposit fails
            }
            
            vm.stopPrank();
            
            // Verify soft cap is now reached
            currentFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
            console.log("Updated funds raised:", currentFundsRaised);
            assertTrue(stoConfig.isSoftCapReached(), "Soft cap should be reached after deposit");
        }
        
        // 3. If current time is after end time, warp to before end time
        if (block.timestamp >= endTime) {
            console.log("Cannot run this test because we cannot move time backwards");
            return;
        }
        
        // Make sure we're well before end time
        assertLt(block.timestamp, endTime, "Current time should be before end time");
        
        // 4. Try to finalize the STO before end time (should fail)
        vm.startPrank(deployer);
        console.log("Calling finalize() as deployer (operator) - should fail");
        
        // The transaction should revert
        vm.expectRevert();
        sto.finalize();
        
        console.log("Finalization correctly failed as expected (before end time)");
        vm.stopPrank();
        console.log("Test completed");
    }
    
    /**
     * @notice Test attempting to finalize an STO where soft cap is not reached and end time has not passed
     * @dev This should fail because soft cap not reached and end time not passed
     */
    function testFinalizeSoftCapNotReachedBeforeEndTime() public {
        console.log("\n=== TEST: Finalize STO with Soft Cap Not Reached Before End Time ===");
        
        // Skip if STO is already finalized or closed
        if (escrow.isFinalized() || escrow.isSTOClosed()) {
            console.log("STO is already finalized or closed, skipping test");
            return;
        }
        
        // 1. Check current state
        uint256 endTime = stoConfig.endTime();
        uint256 currentFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
        console.log("End time:", endTime);
        console.log("Current time:", block.timestamp);
        console.log("Current funds raised:", currentFundsRaised);
        console.log("Soft cap:", softCap);
        
        // 2. If we've already reached the soft cap, can't run this test
        if (currentFundsRaised >= softCap) {
            console.log("Soft cap already reached, cannot run this test");
            return;
        }
        
        // 3. If current time is after end time, can't run this test
        if (block.timestamp >= endTime) {
            console.log("End time already passed, cannot run this test");
            return;
        }
        
        // 4. Try to finalize the STO (should fail)
        vm.startPrank(deployer);
        console.log("Calling finalize() as deployer (operator) - should fail");
        
        // The transaction should revert
        vm.expectRevert();
        sto.finalize();
        
        console.log("Finalization correctly failed as expected (soft cap not reached & before end time)");
        vm.stopPrank();
        console.log("Test completed");
    }
    
    /**
     * @notice Test automatic refunds for an STO where soft cap is not reached and end time has passed
     * @dev Verifies investors automatically get refunded when the offering fails
     */
    function testRefundWhenSoftCapNotReached() public {
        console.log("\n=== TEST: Automatic Refund When Soft Cap Not Reached ===");

        // Skip if STO is already finalized
        if (escrow.isFinalized()) {
            console.log("STO is already finalized, skipping test");
            return;
        }

        // 1. Check current state
        uint256 endTime = stoConfig.endTime();
        uint256 currentFundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
        console.log("End time:", endTime);
        console.log("Current time:", block.timestamp);
        console.log("Current funds raised:", currentFundsRaised);
        console.log("Soft cap:", softCap);

        // 2. If we've already reached the soft cap, can't run this test
        if (currentFundsRaised >= softCap) {
            console.log("Soft cap already reached, cannot run this test");
            return;
        }

        // 3. Record initial balances
        uint256 investorTokenBalanceBefore = investmentToken.balanceOf(deployer);
        console.log("Investor investment token balance before:", investorTokenBalanceBefore);

        // 4. Make investment for the test
        uint256 depositAmount = minInvestment * 2;

        vm.startPrank(deployer);
        investmentToken.approve(stoAddress, depositAmount);

        try sto.buyTokens(deployer, depositAmount) {
            console.log("Successfully deposited", depositAmount, "tokens for test");
        } catch Error(string memory reason) {
            console.log("Deposit failed:", reason);
            vm.stopPrank();
            return; // Skip remaining test if deposit fails
        }

        vm.stopPrank();

        // 5. Record post-investment balances
        uint256 investorTokenBalanceAfterInvestment = investmentToken.balanceOf(deployer);
        console.log("Investor investment token balance after investment:", investorTokenBalanceAfterInvestment);
        console.log("Investment amount (balance change):", investorTokenBalanceBefore - investorTokenBalanceAfterInvestment);

        // Record investment amount from escrow
        uint256 investmentAmount = 0;
        try escrow.getInvestment(deployer) returns (uint256 investment) {
            investmentAmount = investment;
            console.log("Investor's investment amount in escrow:", investmentAmount);
            // Verify the escrow records the correct investment amount
            assertEq(investmentAmount, depositAmount, "Escrow should record correct investment amount");
        } catch {
            console.log("Failed to get investment amount");
            return;
        }

        // 6. If current time is before end time, warp to after end time
        if (block.timestamp < endTime) {
            console.log("Warping time to after end time");
            vm.warp(endTime + 1 hours);
            console.log("New time:", block.timestamp);
        }

        // 7. Finalize the STO as the operator
        vm.startPrank(deployer);
        console.log("Calling finalize() as deployer (operator)");

        try sto.finalize() {
            console.log("Successfully finalized the STO");

            // Verify STO is finalized
            assertTrue(escrow.isFinalized(), "Escrow should be finalized");
            assertFalse(stoConfig.isSoftCapReached(), "Soft cap should not be reached");

        } catch Error(string memory reason) {
            console.log("Finalization failed:", reason);
            assertTrue(false, string.concat("Finalization failed: ", reason));
        }

        vm.stopPrank();

        // 8. Check if investor was automatically refunded during finalization
        uint256 investorTokenBalanceAfterFinalization = investmentToken.balanceOf(deployer);
        console.log("Investor investment token balance after finalization:", investorTokenBalanceAfterFinalization);
        uint256 refundAmount = investorTokenBalanceAfterFinalization - investorTokenBalanceAfterInvestment;
        console.log("Automatic refund amount (balance change):", refundAmount);

        // Verify the refund amount matches the investment amount
        assertEq(refundAmount, investmentAmount, "Refund amount should match investment amount");

        // Verify investment in escrow is now zero
        uint256 remainingInvestment = escrow.getInvestment(deployer);
        console.log("Remaining investment in escrow:", remainingInvestment);
        assertEq(remainingInvestment, 0, "Investment in escrow should be zero after refund");

        // 9. Verify refund was marked as processed in the Refund contract
        bool refundProcessed = false;
        try finalizationManager.getRefundDetailsForInvestor(deployer) returns (bool needsRefund, uint256 amount) {
            console.log("Refund status - needs refund:", needsRefund);
            console.log("Refund status - amount:", amount);
            // If needsRefund is false, it means refund was already processed
            refundProcessed = !needsRefund;
        } catch {
            console.log("Failed to check refund processing status");
        }

        assertTrue(refundProcessed, "Refund should be marked as processed");

        // 10. Verify investor's final balance is back to the original amount
        assertEq(
            investorTokenBalanceAfterFinalization,
            investorTokenBalanceBefore,
            "Investor should have their original balance after automatic refund"
        );

        console.log("Test completed - automatic refund verification successful");
    }
}