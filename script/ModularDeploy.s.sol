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
 * @title Modular STO Deployment Script
 * @notice Deploys a Security Token Offering (STO) following best practices for modular contracts
 * @dev This script follows the deployment pattern used in major protocols like Compound and Aave:
 *      1. Deploy the core contract first
 *      2. Deploy modules with the core contract's address
 *      3. Register modules with the core
 *      4. Set up cross-module dependencies
 */
/*
contract ModularDeployScript is Script {
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

        // Calculate start and end times
        uint256 startTime = block.timestamp + START_TIME_BUFFER;
        uint256 endTime = startTime + OFFERING_DURATION;

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
        console.log("Current timestamp:", block.timestamp);
        console.log("Start time:", startTime);
        console.log("End time:", endTime);

        // -----------------------------------------------------------------
        // STEP 1: Deploy the STO Factory and Implementation
        // -----------------------------------------------------------------
        console.log("\nStep 1: Deploying STO Factory and Implementation...");
        
        // First, create a minimal implementation to use with the factory
        // This implementation won't be used directly but serves as a template
        CappedSTO stoImplementation = new CappedSTO(
            securityToken,    // Security token
            IS_RULE_506C,     // Rule 506c flag
            investmentToken,  // Investment token
            deployer,         // Placeholder for escrow
            deployer,         // Placeholder for refund
            deployer,         // Placeholder for minting
            deployer,         // Placeholder for pricing logic
            deployer,         // Placeholder for fees
            deployer,         // Placeholder for investment manager
            deployer,         // Placeholder for finalization manager
            deployer,         // Placeholder for verification manager
            deployer,         // Placeholder for compliance
            deployer          // Placeholder for STO config
        );
        console.log("STO Implementation deployed at:", address(stoImplementation));
        
        // Deploy the factory
        STOFactory factory = new STOFactory(address(stoImplementation));
        console.log("STO Factory deployed at:", address(factory));
        
        // -----------------------------------------------------------------
        // STEP 2: Deploy STO via Factory
        // -----------------------------------------------------------------
        console.log("\nStep 2: Deploying STO via Factory...");
        
        // Deploy STO using the factory to get the actual STO instance
        (bytes32 deploymentId, address stoAddress) = factory.deploySTOWithParams(
            securityToken,         // _securityToken
            IS_RULE_506C,          // _isRule506c
            startTime,             // _startTime
            endTime,               // _endTime
            hardCap,               // _hardCap
            softCap,               // _softCap
            rate,                  // _rate
            payable(deployer),     // _fundsReceiver
            investmentToken,       // _investmentToken
            FEE_RATE,              // _feeRate
            deployer,              // _feeWallet
            deployer,              // _owner
            minInvestment          // _minInvestment
        );
        console.log("STO deployed at:", stoAddress);
        console.log("Deployment ID:", vm.toString(deploymentId));
        
        // Get the actual STO contract instance
        CappedSTO sto = CappedSTO(payable(stoAddress));
        
        // -----------------------------------------------------------------
        // STEP 3: Get Factory-Deployed Components
        // -----------------------------------------------------------------
        console.log("\nStep 3: Retrieving Factory-Deployed Components...");
        
        // Get the components that were automatically deployed by the factory
        STOFactory.STODeploymentInfo memory info = factory.getDeploymentInfo(deploymentId);
        
        // The factory should have deployed these components automatically:
        address fixedPriceAddress = info.fixedPrice;
        address mintingAddress = info.minting;
        address refundAddress = info.refund;
        address escrowAddress = info.escrow;
        address feesAddress = info.fees;
        
        console.log("Factory-Deployed Components:");
        console.log("- Fixed Price Logic:", fixedPriceAddress);
        console.log("- Minting Contract:", mintingAddress);
        console.log("- Refund Contract:", refundAddress);
        console.log("- Escrow Contract:", escrowAddress);
        console.log("- Fees Contract:", feesAddress);
        
        // Get contract instances for these components
        FixedPrice fixedPrice = FixedPrice(fixedPriceAddress);
        Minting minting = Minting(mintingAddress);
        Refund refund = Refund(refundAddress);
        Escrow escrow = Escrow(escrowAddress);
        Fees fees = Fees(feesAddress);
        
        // -----------------------------------------------------------------
        // STEP 4: Deploy Additional Components
        // -----------------------------------------------------------------
        console.log("\nStep 4: Deploying Additional Components...");
        
        // Create STO Config with the real STO address
        STOConfig stoConfig = new STOConfig(
            stoAddress,
            securityToken,
            IS_RULE_506C
        );
        console.log("STOConfig deployed at:", address(stoConfig));
        
        // Configure the STOConfig with the correct parameters
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
        
        // Deploy VerificationManager
        VerificationManager verificationManager = new VerificationManager(
            stoAddress,
            securityToken,
            IS_RULE_506C
        );
        console.log("VerificationManager deployed at:", address(verificationManager));
        
        // Try to set the attribute registry if available
        try IToken(securityToken).attributeRegistry() returns (IAttributeRegistry attributeRegistry) {
            if (address(attributeRegistry) != address(0)) {
                verificationManager.setAttributeRegistry(address(attributeRegistry));
                console.log("VerificationManager initialized with attribute registry");
            }
        } catch {
            console.log("Failed to get attribute registry from security token");
        }
        
        // Deploy Compliance
        Compliance compliance = new Compliance(deployer);
        console.log("Compliance deployed at:", address(compliance));
        
        // Deploy InvestmentManager
        InvestmentManager investmentManager = new InvestmentManager(
            stoAddress,
            securityToken,
            investmentToken,
            address(escrow),
            address(fixedPrice),
            IS_RULE_506C,
            address(verificationManager),
            address(compliance)
        );
        console.log("InvestmentManager deployed at:", address(investmentManager));
        
        // Set the STOConfig in the InvestmentManager
        investmentManager.setSTOConfig(address(stoConfig));
        
        // Deploy FinalizationManager
        FinalizationManager finalizationManager = new FinalizationManager(
            stoAddress,
            securityToken,
            address(escrow),
            address(minting),
            address(refund),
            IS_RULE_506C
        );
        console.log("FinalizationManager deployed at:", address(finalizationManager));
        
        // Set the STOConfig in the FinalizationManager
        finalizationManager.setSTOConfig(address(stoConfig));
        
        // -----------------------------------------------------------------
        // STEP 5: Update Cross-Module Dependencies
        // -----------------------------------------------------------------
        console.log("\nStep 5: Updating Cross-Module Dependencies...");
        
        // Update Refund with Escrow
        try refund.updateEscrow(address(escrow)) {
            console.log("- Updated Refund with Escrow");
        } catch {
            console.log("! Failed to update Refund with Escrow");
        }
        
        // Update Minting with Escrow
        try minting.updateEscrow(address(escrow)) {
            console.log("- Updated Minting with Escrow");
        } catch {
            console.log("! Failed to update Minting with Escrow");
        }
        
        // -----------------------------------------------------------------
        // STEP 6: Register Modules with STO
        // -----------------------------------------------------------------
        console.log("\nStep 6: Registering Components with STO...");

        // Note: The STO usually needs to be made aware of key components.
        // However, with the proxy-based approach of the factory, most connections
        // are already established. We would add any remaining registrations here if needed.
        
        // -----------------------------------------------------------------
        // STEP 7: Register STO as agent on the security token
        // -----------------------------------------------------------------
        console.log("\nStep 7: Registering STO as agent on security token...");
        
        try sto.registerAsAgent() {
            console.log("STO registered as agent on the security token");
        } catch {
            console.log("Failed to register STO as agent - manual registration may be needed");
        }
        
        vm.stopBroadcast();
        
        // -----------------------------------------------------------------
        // STEP 8: Display Deployment Summary
        // -----------------------------------------------------------------
        console.log("\nDeployment Summary:");
        console.log("Security Token:", securityToken);
        console.log("STO Address:", stoAddress);
        console.log("Investment Token:", investmentToken);
        console.log("Fixed Price Logic:", address(fixedPrice));
        console.log("Minting Contract:", address(minting));
        console.log("Refund Contract:", address(refund));
        console.log("Escrow Contract:", address(escrow));
        console.log("Fees Contract:", address(fees));
        console.log("STOConfig:", address(stoConfig));
        console.log("VerificationManager:", address(verificationManager));
        console.log("Compliance:", address(compliance));
        console.log("InvestmentManager:", address(investmentManager));
        console.log("FinalizationManager:", address(finalizationManager));
        
        console.log("\n=== NEXT STEPS ===");
        console.log("1. The STO is now deployed and ready to accept investments");
        console.log("2. Verify the STO contract on Etherscan/Polygonscan");
        console.log("3. Verify investors through the VerificationManager");
        console.log("4. If the STO is not registered as an agent, register it manually");
    }
}
*/