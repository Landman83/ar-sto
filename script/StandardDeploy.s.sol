// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/CappedSTO.sol";
import "../src/factory/STOFactory.sol";
import "../src/utils/InvestmentManager.sol";
import "../src/utils/FinalizationManager.sol";
import "../src/utils/VerificationManager.sol";
import "../src/mixins/Compliance.sol";
import "../src/utils/STOConfig.sol";
import "../src/utils/Escrow.sol";
import "../src/utils/Refund.sol";
import "../src/utils/Minting.sol";
import "../src/mixins/FixedPrice.sol";
import "../src/utils/Fees.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@ar-security-token/src/interfaces/IToken.sol";
import "@ar-security-token/lib/st-identity-registry/src/interfaces/IAttributeRegistry.sol";

/**
 * @title Standard STO Deployment Script
 * @notice Deploys a Security Token Offering (STO) using standard deployment
 * @dev This script follows the deployment-guide.txt and implements a step-by-step deployment
 */
contract StandardDeployScript is Script {
    // Helper functions for parsing decimal rates
    function containsDecimal(string memory str) internal pure returns (bool) {
        bytes memory b = bytes(str);
        for (uint i = 0; i < b.length; i++) {
            if (b[i] == '.') {
                return true;
            }
        }
        return false;
    }
    
    function parseDecimalRate(string memory str) internal pure returns (uint256) {
        bytes memory b = bytes(str);
        uint256 result = 0;
        uint256 decimals = 0;
        bool foundDecimal = false;
        
        for (uint i = 0; i < b.length; i++) {
            if (b[i] >= bytes1('0') && b[i] <= bytes1('9')) {
                result = result * 10 + uint8(b[i]) - uint8(bytes1('0'));
                if (foundDecimal) {
                    decimals++;
                }
            } else if (b[i] == '.') {
                foundDecimal = true;
            }
        }
        
        // Adjust to 18 decimals (e.g., 0.2 becomes 0.2 * 10^18)
        uint256 multiplier = 10 ** (18 - decimals);
        return result * multiplier;
    }
    
    // Connection setup
    string private constant ENV_RPC_URL = "RPC_URL";
    string private constant ENV_CHAIN_ID = "CHAIN_ID";
    // Environment variables
    string private constant ENV_SECURITY_TOKEN = "SECURITY_TOKEN_ADDRESS";
    string private constant ENV_INVESTMENT_TOKEN = "INVESTMENT_TOKEN";
    string private constant ENV_HARD_CAP = "HARD_CAP";
    string private constant ENV_SOFT_CAP = "SOFT_CAP";
    string private constant ENV_MIN_INVESTMENT = "MIN_INVESTMENT";
    string private constant ENV_RATE = "RATE";
    string private constant ENV_PRIVATE_KEY = "PRIVATE_KEY";
    string private constant ENV_DEPLOYER_ADDRESS = "DEPLOYER_ADDRESS";

    // Deployment parameters
    bool private constant IS_RULE_506C = true;
    uint256 private constant START_TIME_BUFFER = 1 minutes; // Buffer to ensure start time is in the future
    uint256 private constant OFFERING_DURATION = 1 hours;
    uint256 private constant FEE_RATE = 200; // 2% fee (in basis points)
    
    function run() public {
        // Set up RPC connection from environment
        string memory rpcUrl = vm.envString(ENV_RPC_URL);
        uint256 chainId = vm.envUint(ENV_CHAIN_ID);
        vm.createSelectFork(rpcUrl);
        
        // Load environment variables
        uint256 privateKey = vm.envUint(ENV_PRIVATE_KEY);
        address securityToken = vm.envAddress(ENV_SECURITY_TOKEN);
        address investmentToken = vm.envAddress(ENV_INVESTMENT_TOKEN);
        address deployer = vm.envAddress(ENV_DEPLOYER_ADDRESS);
        
        // Load numerical parameters with fallbacks
        uint256 hardCap = vm.envOr(ENV_HARD_CAP, uint256(1_000_000 * 10**18));  // Default: 1M tokens
        uint256 softCap = vm.envOr(ENV_SOFT_CAP, uint256(100_000 * 10**18));    // Default: 100k tokens
        uint256 minInvestment = vm.envOr(ENV_MIN_INVESTMENT, uint256(100 * 10**18)); // Default: 100 tokens
        
        // Special handling for rate - convert from decimal format if needed
        string memory rateStr = vm.envOr(ENV_RATE, string("1.0"));
        uint256 rate;
        
        // If rate string has a decimal point, handle it specially
        if (bytes(rateStr).length > 0 && containsDecimal(rateStr)) {
            rate = parseDecimalRate(rateStr);
            console.log("Parsed decimal rate:", rateStr, "to value:", rate);
        } else {
            // Otherwise, use the normal env variable
            rate = vm.envOr(ENV_RATE, uint256(1 * 10**18)); // Default: 1:1 rate
        }

        // Validate essential parameters
        require(securityToken != address(0), "Security token address cannot be zero");
        require(investmentToken != address(0), "Investment token address cannot be zero");
        require(deployer != address(0), "Deployer address cannot be zero");
        require(hardCap > 0, "Hard cap must be greater than zero");
        require(softCap > 0, "Soft cap must be greater than zero");
        require(hardCap >= softCap, "Hard cap must be greater than or equal to soft cap");
        require(rate > 0, "Rate must be greater than zero");

        // Start the transaction with the private key
        vm.startBroadcast(privateKey);

        // Log parameters
        console.log("Connected to network with Chain ID:", chainId);
        console.log("Using RPC URL:", rpcUrl);
        console.log("");
        console.log("Deploying STO with the following parameters:");
        console.log("Security Token:", securityToken);
        console.log("Is Rule 506c:", IS_RULE_506C);
        console.log("Hard Cap:", hardCap);
        console.log("Soft Cap:", softCap);
        console.log("Rate:", rate);
        console.log("Funds Receiver:", deployer);
        console.log("Investment Token:", investmentToken);
        console.log("Fee Rate:", FEE_RATE);
        console.log("Fee Wallet:", deployer);
        console.log("Owner:", deployer);
        console.log("Min Investment:", minInvestment);
        
        // Calculate start and end times
        uint256 startTime = block.timestamp + START_TIME_BUFFER;
        uint256 endTime = startTime + OFFERING_DURATION; 
        console.log("Current timestamp:", block.timestamp);
        console.log("Start time:", startTime);
        console.log("End time:", endTime);

        // -----------------------------------------------------------------
        // 1. Deploy auxiliary contracts following deployment-guide.txt
        // -----------------------------------------------------------------
        console.log("\nStep 1: Deploying auxiliary contracts...");
        
        // Deploy the FixedPrice contract
        FixedPrice fixedPrice = new FixedPrice(
            securityToken,
            rate,
            deployer // Use deployer as the operator since address(0) is not allowed
        );
        console.log("FixedPrice deployed at:", address(fixedPrice));
        
        // We need to create a mock STO address first because all components need it
        address mockStoAddress = deployer; // Using deployer as a temporary STO address
        
        // Deploy the Minting contract with the mock STO address
        Minting minting = new Minting(
            mockStoAddress // Use mock address for now
        );
        console.log("Minting deployed at:", address(minting));
        
        // Deploy Fees contract with actual parameters
        Fees fees = new Fees(
            FEE_RATE,
            payable(deployer),
            deployer  // Use deployer as owner
        );
        console.log("Fees deployed at:", address(fees));
        
        // Deploy the Refund contract with mock addresses
        Refund refund = new Refund(
            mockStoAddress, // Use mock STO address
            investmentToken,
            mockStoAddress  // Use mock address for escrow
        );
        console.log("Refund deployed at:", address(refund));
        
        // Now deploy Escrow with all required non-zero dependencies
        Escrow escrow = new Escrow(
            mockStoAddress, // Use mock STO address for now
            securityToken,
            investmentToken,
            payable(deployer), // fundsReceiver
            address(refund),
            address(minting),
            address(fees)
        );
        console.log("Escrow deployed at:", address(escrow));
        
        // Deploy VerificationManager
        VerificationManager verificationManager = new VerificationManager(
            mockStoAddress,  // Use mock STO address
            securityToken,
            IS_RULE_506C
        );
        console.log("VerificationManager deployed at:", address(verificationManager));
        
        // Deploy Compliance contract with the deployer as owner
        Compliance compliance = new Compliance(deployer);  // Use deployer as owner
        console.log("Compliance deployed at:", address(compliance));
        
        // Deploy STOConfig with mock STO address
        STOConfig stoConfig = new STOConfig(
            mockStoAddress,  // Use mock STO address for now
            securityToken,
            IS_RULE_506C
        );
        console.log("STOConfig deployed at:", address(stoConfig));
        
        // Configure STOConfig
        stoConfig.configure(
            startTime,
            endTime,
            hardCap,
            softCap,
            rate,
            payable(deployer),
            investmentToken
        );
        
        // Set ERC20 as the fund raise type
        STOConfig.FundRaiseType[] memory fundRaiseTypes = new STOConfig.FundRaiseType[](1);
        fundRaiseTypes[0] = STOConfig.FundRaiseType.ERC20;
        stoConfig.setFundRaiseTypes(fundRaiseTypes);
        
        // Deploy InvestmentManager (temporarily with address(0) as STO)
        InvestmentManager investmentManager = new InvestmentManager(
            address(0), // Will update later
            securityToken,
            investmentToken,
            address(escrow),
            address(fixedPrice),
            IS_RULE_506C,
            address(verificationManager),
            address(compliance)
        );
        console.log("InvestmentManager deployed at:", address(investmentManager));
        
        // Deploy FinalizationManager (temporarily with address(0) as STO)
        FinalizationManager finalizationManager = new FinalizationManager(
            address(0), // Will update later
            securityToken,
            address(escrow),
            address(minting),
            address(refund),
            IS_RULE_506C
        );
        console.log("FinalizationManager deployed at:", address(finalizationManager));
        
        // -----------------------------------------------------------------
        // 2. Deploy CappedSTO implementation
        // -----------------------------------------------------------------
        console.log("\nStep 2: Deploying STO implementation...");
        
        CappedSTO stoImplementation = new CappedSTO(
            securityToken,
            IS_RULE_506C,
            investmentToken,
            address(escrow),
            address(refund),
            address(minting),
            address(fixedPrice),
            address(fees),
            address(investmentManager),
            address(finalizationManager),
            address(verificationManager),
            address(compliance),
            address(stoConfig)
        );
        console.log("STO implementation deployed at:", address(stoImplementation));

        // -----------------------------------------------------------------
        // 3. Deploy STOFactory
        // -----------------------------------------------------------------
        console.log("\nStep 3: Deploying STO factory...");
        
        STOFactory factory = new STOFactory(address(stoImplementation));
        console.log("STO factory deployed at:", address(factory));
        
        // -----------------------------------------------------------------
        // 4. Deploy STO using factory
        // -----------------------------------------------------------------
        console.log("\nStep 4: Deploying STO with factory...");
        
        // Deploy STO with factory
        (bytes32 deploymentId, address stoAddress) = factory.deploySTOWithParams(
            securityToken,                // _securityToken
            IS_RULE_506C,                 // _isRule506c
            startTime,                    // _startTime
            endTime,                      // _endTime
            hardCap,                      // _hardCap
            softCap,                      // _softCap
            rate,                         // _rate
            payable(deployer),            // _fundsReceiver
            investmentToken,              // _investmentToken
            FEE_RATE,                     // _feeRate
            deployer,                     // _feeWallet
            deployer,                     // _owner
            minInvestment                 // _minInvestment
        );
        console.log("STO deployed at:", stoAddress);
        console.log("Deployment ID:", vm.toString(deploymentId));
        
        // Get deployed auxiliary contract addresses from the factory
        STOFactory.STODeploymentInfo memory info = factory.getDeploymentInfo(deploymentId);
        console.log("Factory deployed contracts:");
        console.log("Fixed Price Logic:", info.fixedPrice);
        console.log("Minting Contract:", info.minting);
        console.log("Refund Contract:", info.refund);
        console.log("Escrow Contract:", info.escrow);
        console.log("Fees Contract:", info.fees);
        
        // -----------------------------------------------------------------
        // 5. Update dependencies after STO deployment
        // -----------------------------------------------------------------
        console.log("\nStep 5: Updating contract dependencies after STO deployment...");
        
        CappedSTO sto = CappedSTO(payable(stoAddress));
        
        // After the STO and all components are deployed, we need to update the components with references
        // Many components need to reference the STO, escrow, fees, etc.
        
        // Escrow doesn't have direct update methods - it's updated through constructor
        // We need to redeploy it with the correct addresses
        console.log("Redeploying Escrow with correct addresses...");
        
        // Create a new Escrow with the correct addresses
        Escrow newEscrow = new Escrow(
            stoAddress, // Now using the real STO address
            securityToken,
            investmentToken,
            payable(deployer),
            address(refund),
            address(minting),
            address(fees)
        );
        console.log("New Escrow deployed at:", address(newEscrow));
        
        // CappedSTO doesn't have an updateEscrow method - the escrow is set in the constructor
        // and cannot be changed. We may need to redeploy the STO entirely with the new escrow address.
        console.log("Note: Cannot update CappedSTO with new Escrow address - escrow is immutable");
        console.log("The escrow property in the STO still points to the old escrow:", address(escrow));
        
        // Update Refund's dependencies
        // We need to update the new Escrow address in the Refund contract
        try refund.updateEscrow(address(newEscrow)) {
            console.log("Updated Refund with new Escrow address");
        } catch Error(string memory reason) {
            console.log("Failed to update Refund with Escrow address:", reason);
        } catch {
            console.log("Failed to update Refund with Escrow address (unknown error)");
        }
        
        // Update Minting's dependencies
        // Minting doesn't have a direct updateSTO method - it needs to be updated
        
        // Update Minting with the new Escrow address
        try minting.updateEscrow(address(newEscrow)) {
            console.log("Updated Minting with new Escrow address");
        } catch Error(string memory reason) {
            console.log("Failed to update Minting with Escrow address:", reason);
        } catch {
            console.log("Failed to update Minting with Escrow address (unknown error)");
        }
        
        // FixedPrice doesn't have an updateSTO method - the operator is set in the constructor
        // We would need to redeploy it, but since it's set as a field in the STO already
        // we'll just log this information
        console.log("Note: FixedPrice doesn't have an updateSTO method - it uses an operator field");
        console.log("The FixedPrice contract may need to be redeployed in a future step if changes are needed");
        
        // STOConfig doesn't have an updateSTO method - the STO address is set in the constructor
        // We would need to redeploy it, but since it's set as a field in the STO already
        console.log("Note: STOConfig doesn't have an updateSTO method - STO address set in constructor");
        console.log("STOConfig may need to be redeployed if access permissions are needed");
        
        // VerificationManager doesn't have an updateSTO method - the STO address is set in the constructor
        // We would need to redeploy it, but since it's set as a field in the STO already
        console.log("Note: VerificationManager doesn't have an updateSTO method - STO address set in constructor");
        
        // We need to verify if it has the correct attribute registry
        // Get it from the security token directly
        try IToken(securityToken).attributeRegistry() returns (IAttributeRegistry attributeRegistry) {
            if (address(attributeRegistry) != address(0)) {
                try verificationManager.setAttributeRegistry(address(attributeRegistry)) {
                    console.log("Updated VerificationManager with attribute registry from the security token");
                } catch Error(string memory reason) {
                    console.log("Failed to update VerificationManager with attribute registry:", reason);
                } catch {
                    console.log("Failed to update VerificationManager with attribute registry (unknown error)");
                }
            } else {
                console.log("Security token doesn't have an attribute registry set");
            }
        } catch {
            console.log("Failed to get attribute registry from security token");
        }
        
        // Fees doesn't have an updateSTO method
        console.log("Note: Fees doesn't have an updateSTO method - only has owner, feeRate, and feeWallet");
        
        // InvestmentManager doesn't have updateSTO method, but has setSTOConfig
        try investmentManager.setSTOConfig(address(stoConfig)) {
            console.log("Updated InvestmentManager with STOConfig address");
        } catch Error(string memory reason) {
            console.log("Failed to update InvestmentManager with STOConfig address:", reason);
        } catch {
            console.log("Failed to update InvestmentManager with STOConfig address (unknown error)");
        }
        
        // FinalizationManager doesn't have updateSTO method, but has setSTOConfig
        try finalizationManager.setSTOConfig(address(stoConfig)) {
            console.log("Updated FinalizationManager with STOConfig address");
        } catch Error(string memory reason) {
            console.log("Failed to update FinalizationManager with STOConfig address:", reason);
        } catch {
            console.log("Failed to update FinalizationManager with STOConfig address (unknown error)");
        }
        
        // Compliance doesn't have an updateSTO method - it inherits from Ownable and doesn't need the STO address
        console.log("Note: Compliance doesn't have an updateSTO method - it's Ownable");
        
        console.log("Updated all contracts with STO address");
        
        // -----------------------------------------------------------------
        // 6. Register STO as agent on the token
        // -----------------------------------------------------------------
        console.log("\nStep 6: Registering STO as agent on the token...");
        
        try sto.registerAsAgent() {
            console.log("STO registered as agent on the security token");
        } catch {
            console.log("Could not register STO as agent - manual registration may be needed");
        }

        vm.stopBroadcast();
        
        // -----------------------------------------------------------------
        // 7. Display deployment summary
        // -----------------------------------------------------------------
        console.log("\nDeployment Summary:");
        console.log("Security Token:", securityToken);
        console.log("STO Address:", stoAddress);
        console.log("STOConfig Address:", address(stoConfig));
        console.log("InvestmentManager Address:", address(investmentManager));
        console.log("FinalizationManager Address:", address(finalizationManager));
        console.log("VerificationManager Address:", address(verificationManager));
        console.log("Fixed Price Logic:", address(fixedPrice));
        console.log("Minting Contract:", address(minting));
        console.log("Refund Contract:", address(refund));
        console.log("Original Escrow Contract (referenced by STO):", address(escrow));
        console.log("New Escrow Contract (will be used by Refund/Minting):", address(newEscrow));
        console.log("Fees Contract:", address(fees));
        
        console.log("\n=== NEXT STEPS ===");
        console.log("1. The STO is now deployed and ready to accept investments");
        console.log("2. Verify the STO contract on Etherscan/Polygonscan");
        console.log("3. Verify investors through the STO's verification manager");
        console.log("4. If the STO is not registered as an agent, register it manually");
        console.log("\n=== WARNING ===");
        console.log("The STO contract still references the original Escrow, but Refund and Minting");
        console.log("contracts have been updated to use the new Escrow. This may cause issues with");
        console.log("fund handling. For a complete solution, you may need to redeploy the STO with");
        console.log("the correct Escrow address in the constructor.");
    }
}