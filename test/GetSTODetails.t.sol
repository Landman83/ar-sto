// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/CappedSTO.sol";
import "../src/interfaces/ISTO.sol";
import "../src/interfaces/ISTOConfig.sol";
import "../src/utils/InvestmentManager.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Extend IERC20 interface to include metadata functions
interface IERC20Extended is IERC20 {
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}

// Interface for InvestmentManager to access methods
interface TestInvestmentManager {
    function getAllInvestors() external view returns (address[] memory);
}

// Interface for Escrow to access methods (using TestEscrow name to avoid conflicts)
interface TestEscrow {
    function deposits(address investor) external view returns (uint256);
}

contract GetSTODetailsTest is Test {
    ISTO public sto;
    address payable public stoAddress;
    
    function setUp() public {
        // Load the STO address and RPC URL from environment variables
        string memory stoAddressStr = vm.envString("STO_ADDRESS");
        string memory rpcUrl = vm.envString("RPC_URL");
        
        require(bytes(stoAddressStr).length > 0, "STO_ADDRESS not set in .env");
        require(bytes(rpcUrl).length > 0, "RPC_URL not set in .env");
        
        // Configure fork from RPC URL
        vm.createSelectFork(rpcUrl);
        
        stoAddress = payable(vm.parseAddress(stoAddressStr));
        sto = ISTO(stoAddress);
    }
    
    function testGetSTODetails() public {
        // Display useful debugging info before starting
        console.log("Testing STO at address:", stoAddress);
        console.log("Block number:", block.number);
        console.log("Block timestamp:", block.timestamp);
        
        // Check if the contract exists and has code
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(sload(stoAddress.slot))
        }
        console.log("Contract code size:", codeSize);
        require(codeSize > 0, "STO contract has no code at the specified address");
        
        // First try basic calls to see if the contract responds
        try CappedSTO(stoAddress).securityToken() returns (address secToken) {
            console.log("Security token address:", secToken);
        } catch Error(string memory reason) {
            console.log("Error calling securityToken():", reason);
        } catch (bytes memory) {
            console.log("Low-level error calling securityToken()");
        }
        
        // We need to cast to CappedSTO to access getSTODetails
        CappedSTO cappedSTO = CappedSTO(stoAddress);
        
        // Call the getSTODetails function with try/catch for better error reporting
        try cappedSTO.getSTODetails() returns (
            uint256 startTime,
            uint256 endTime,
            uint256 hardCap,
            uint256 softCap,
            uint256 currentRate,
            uint256 fundsRaised,
            uint256 investorCount,
            uint256 tokensSold,
            address investmentToken,
            bool softCapReached,
            bool stoClosed
        ) {
        
            // Log the details for visibility
            console.log("STO Details:");
            console.log("Start Time:", startTime);
            console.log("End Time:", endTime);
            console.log("Hard Cap:", hardCap);
            console.log("Soft Cap:", softCap);
            console.log("Current Rate:", currentRate);
            console.log("Funds Raised:", fundsRaised);
            console.log("Investor Count:", investorCount);
            console.log("Tokens Sold:", tokensSold);
            console.log("Investment Token:", investmentToken);
            console.log("Soft Cap Reached:", softCapReached);
            console.log("STO Closed:", stoClosed);
            
            // Basic validation of the returned values
            assertGe(endTime, startTime, "End time should be greater than or equal to start time");
            assertGe(hardCap, softCap, "Hard cap should be greater than or equal to soft cap");
            
            if (softCapReached) {
                assertGe(fundsRaised, softCap, "If soft cap is reached, funds raised should be >= soft cap");
            }
            
            // Check STO state consistency
            if (stoClosed) {
                uint256 currentTime = block.timestamp;
                if (!(softCapReached || currentTime > endTime)) {
                    assertTrue(false, "STO is closed but conditions don't match (neither soft cap reached nor end time passed)");
                }
            }
            
            // Get additional contract information
            try cappedSTO.securityToken() returns (address securityTokenAddress) {
                console.log("Security Token Address:", securityTokenAddress);
                
                // Verify the security token matches expected value from .env
                string memory envSecToken = vm.envString("SECURITY_TOKEN_ADDRESS");
                address expectedSecToken = vm.parseAddress(envSecToken);
                console.log("Expected Security Token (from .env):", expectedSecToken);
                
                if (securityTokenAddress != expectedSecToken) {
                    console.log("WARNING: Security token mismatch with .env value");
                }
            } catch {
                console.log("Failed to get security token address");
            }
            
            try cappedSTO.isRule506cOffering() returns (bool isRule506c) {
                console.log("Is Rule 506c Offering:", isRule506c);
            } catch {
                console.log("Failed to get Rule 506c status");
            }
            
            // Check investment token info if available
            if (investmentToken != address(0)) {
                // Verify the investment token matches expected value from .env
                string memory envInvToken = vm.envString("INVESTMENT_TOKEN");
                address expectedInvToken = vm.parseAddress(envInvToken);
                console.log("Expected Investment Token (from .env):", expectedInvToken);
                
                if (investmentToken != expectedInvToken) {
                    console.log("WARNING: Investment token mismatch with .env value");
                }
                
                try IERC20Extended(investmentToken).symbol() returns (string memory symbol) {
                    console.log("Investment Token Symbol:", symbol);
                } catch Error(string memory reason) {
                    console.log("Error getting investment token symbol:", reason);
                } catch {
                    console.log("Could not get investment token symbol");
                }
                
                try IERC20Extended(investmentToken).decimals() returns (uint8 decimals) {
                    console.log("Investment Token Decimals:", decimals);
                } catch Error(string memory reason) {
                    console.log("Error getting investment token decimals:", reason);
                } catch {
                    console.log("Could not get investment token decimals");
                }
            }
            
            // Check if offering is active
            uint256 currentTime = block.timestamp;
            bool isActive = currentTime >= startTime && currentTime <= endTime && !stoClosed;
            console.log("Is Offering Active:", isActive);
            
            // Calculate time remaining if active
            if (isActive) {
                uint256 timeRemaining = endTime - currentTime;
                console.log("Time Remaining (seconds):", timeRemaining);
                console.log("Time Remaining (days):", timeRemaining / 86400);
            }
        } catch Error(string memory reason) {
            console.log("Error calling getSTODetails():", reason);
            
            // Try to determine if this is due to proxy implementation or interface mismatch
            try CappedSTO(stoAddress).getInitFunction() returns (bytes4 selector) {
                console.log("Init function selector:", vm.toString(selector));
                console.log("This appears to be a proxy STO. Verify implementation is correct.");
            } catch {
                console.log("Failed to get init function - likely not a standard STO proxy");
            }
            
            // Check if this could be a problem with the PricingLogic
            try CappedSTO(stoAddress).pricingLogic() returns (PricingLogic pricingLogicContract) {
                console.log("PricingLogic address:", address(pricingLogicContract));
                if (address(pricingLogicContract) == address(0)) {
                    console.log("PricingLogic is not set, which would cause getSTODetails to fail");
                }
            } catch {
                console.log("Failed to check PricingLogic");
            }
            
            // Fail the test with the error message
            assertTrue(false, string.concat("getSTODetails failed: ", reason));
        } catch (bytes memory revertData) {
            console.log("Low-level revert calling getSTODetails");
            console.logBytes(revertData);
            
            // Try to decode the revert data if possible
            if (revertData.length > 4) {
                // This is a simplified selector check - in reality, you would want a more robust decoder
                bytes4 selector;
                assembly {
                    selector := mload(add(revertData, 0x20))
                }
                console.log("Revert selector:", vm.toString(selector));
            }
            
            assertTrue(false, "getSTODetails reverted with no error message");
        }
    }
    
    function testGetInvestorInfo() public {
        // Add diagnostic info
        console.log("Testing investor info for STO at address:", stoAddress);
        
        // We need to cast to CappedSTO to access investor-related functions
        CappedSTO cappedSTO = CappedSTO(stoAddress);
        
        // Try checking if this is a proxy
        try cappedSTO.getInitFunction() returns (bytes4 selector) {
            console.log("This is a proxy STO contract. Init function selector:", vm.toString(selector));
        } catch {
            console.log("Could not determine if this is a proxy contract");
        }
        
        // Try to get basic STO details first
        try cappedSTO.securityToken() returns (address securityToken) {
            console.log("Security token:", securityToken);
        } catch {
            console.log("Could not get security token address");
        }
        
        // Check if this contract has the correct structure by testing different ways to get investor info
        console.log("Attempting to get investor count via different methods:");
        
        // Method 1: Try to access investor count through STOConfig
        // In the new architecture, STOConfig is the source of truth for investor count
        try cappedSTO.getSTOConfig() returns (address stoConfigAddr) {
            console.log("STOConfig found at:", stoConfigAddr);
            
            if (stoConfigAddr != address(0)) {
                try ISTOConfig(stoConfigAddr).investorCount() returns (uint256 count) {
                    console.log("Method 1 - STOConfig investorCount:", count);
                    
                    // Skip if no investors
                    if (count == 0) {
                        console.log("No investors found, skipping investor tests");
                        return;
                    }
                } catch Error(string memory reason) {
                    console.log("Could not get investor count from STOConfig:", reason);
                } catch {
                    console.log("Could not get investor count from STOConfig (low-level error)");
                }
            } else {
                console.log("STOConfig address is zero");
            }
        } catch Error(string memory reason) {
            console.log("Method 1 failed with reason:", reason);
        } catch {
            console.log("Method 1 failed with no reason");
        }
        
        // Method 2: Try through the investment manager
        try cappedSTO.getInvestmentManager() returns (address investmentManagerAddress) {
            InvestmentManager investmentManagerContract = InvestmentManager(investmentManagerAddress);
            console.log("Investment manager found at:", address(investmentManagerContract));
            
            // If we find an investment manager, try to get investors from it
            if (address(investmentManagerContract) != address(0)) {
                try TestInvestmentManager(address(investmentManagerContract)).getAllInvestors() returns (address[] memory invManagerInvestors) {
                    console.log("Method 2 - Investment manager investors:", invManagerInvestors.length);
                } catch {
                    console.log("Could not get investors from investment manager");
                }
            }
        } catch {
            console.log("Could not get investment manager");
        }
        
        // Method 3: Try to get investors from the investment manager directly
        // In the new architecture, InvestmentManager is responsible for tracking investors
        try cappedSTO.getInvestmentManager() returns (address investmentManagerAddr) {
            if (investmentManagerAddr != address(0)) {
                try TestInvestmentManager(investmentManagerAddr).getAllInvestors() returns (address[] memory investors) {
                    console.log("Method 3 - InvestmentManager getAllInvestors found:", investors.length, "investors");
                    
                    if (investors.length > 0) {
                        console.log("First investor address:", investors[0]);
                
                // Check if first investor is verified (if applicable)
                        try cappedSTO.isInvestorVerified(investors[0]) returns (bool isVerified) {
                            console.log("First investor verified:", isVerified);
                        } catch Error(string memory reason) {
                            console.log("Could not check investor verification:", reason);
                        } catch {
                            console.log("Could not check investor verification (low-level error)");
                        }
                
                        // In the new protocol, token receipt status is managed by the finalization manager
                        // Instead of using hasReceivedTokens, let's try to access the finalization manager directly
                        try cappedSTO.getFinalizationManager() returns (address finalizationManagerAddr) {
                            console.log("Finalization manager found at:", finalizationManagerAddr);
                            
                            // We could potentially check token balance directly, but we'll just log this info for now
                            console.log("Note: In the updated protocol, token receipt status is tracked by the finalization manager");
                        } catch Error(string memory reason) {
                            console.log("Could not get finalization manager:", reason);
                        } catch {
                            console.log("Could not get finalization manager (low-level error)");
                        }
                        
                        // Try to get investment amount for this investor (if available)
                        try cappedSTO.escrow() returns (Escrow escrowContract) {
                            console.log("Escrow address:", address(escrowContract));
                            
                            if (address(escrowContract) != address(0)) {
                                try TestEscrow(address(escrowContract)).deposits(investors[0]) returns (uint256 amount) {
                                    console.log("First investor deposit amount:", amount);
                                } catch {
                                    console.log("Could not get investor deposit from escrow");
                                }
                            }
                        } catch {
                            console.log("Could not get escrow address");
                        }
                    }
                } catch Error(string memory reason) {
                    console.log("Method 3 - getAllInvestors failed with reason:", reason);
                } catch {
                    console.log("Method 3 - getAllInvestors failed with no reason");
                }
            } else {
                console.log("Investment manager address is zero");
            }
        } catch Error(string memory reason) {
            console.log("Method 3 failed with reason:", reason);
        } catch {
            console.log("Method 3 failed with no reason");
        }
    }
}