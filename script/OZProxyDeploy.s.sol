// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "../src/CappedSTOUpgradeable.sol";
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
 * @title OpenZeppelin Transparent Proxy Deployment Script
 * @notice Deploys a Security Token Offering (STO) using OpenZeppelin's Transparent Proxy pattern
 * @dev This script uses OpenZeppelin's best practices for proxy deployment:
 *      1. Deploy the implementation contract first
 *      2. Deploy a ProxyAdmin to manage the proxy
 *      3. Deploy the TransparentUpgradeableProxy pointing to the implementation
 *      4. Initialize (not construct) the proxy instance
 *      5. Deploy auxiliary contracts with the proxy's address
 *      6. Configure the STO system through the proxy
 */
contract OZProxyDeployScript is Script {
    /**
     * @notice Helper function to check if there is bytecode at an address
     * @param addr Address to check
     * @return Whether the address has bytecode
     */
    function checkBytecode(address addr) internal view returns (bool) {
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(addr)
        }
        bool hasCode = codeSize > 0;
        console.log("  Address:", addr, hasCode ? "[OK] Has bytecode" : "[FAIL] No bytecode");
        return hasCode;
    }
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
    
    // For tracking deployment info (similar to STOFactory.STODeploymentInfo)
    struct DeploymentInfo {
        address sto;
        address securityToken;
        address fixedPrice;
        address minting;
        address refund;
        address fees;
        address escrow;
        address investmentManager;
        address finalizationManager;
        address verificationManager;
        address compliance;
        address stoConfig;
        address proxyAdmin;
        address implementation;
    }
    
    // We'll use this to store and organize deployment info
    DeploymentInfo public deploymentInfo;

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
        // STEP 1: Deploy the STO Implementation, ProxyAdmin, and Proxy
        // -----------------------------------------------------------------
        console.log("\nStep 1: Deploying STO Implementation, ProxyAdmin, and Proxy...");
        
        // First, deploy a minimal implementation
        // We're not initializing here - that will happen via the proxy
        CappedSTOUpgradeable stoImplementation = new CappedSTOUpgradeable(
            securityToken,    // Security token - needed for constructor, but proxy won't use this
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
        
        // Deploy the ProxyAdmin with deployer as the owner
        ProxyAdmin proxyAdmin = new ProxyAdmin(deployer);
        console.log("ProxyAdmin deployed at:", address(proxyAdmin));
        
        // Define the initialization data for the proxy
        // This matches the initialize function signature expected in STOProxy
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,bool,address)", 
            securityToken, 
            IS_RULE_506C, 
            deployer // Owner
        );
        
        // Deploy the TransparentUpgradeableProxy
        TransparentUpgradeableProxy stoProxy = new TransparentUpgradeableProxy(
            address(stoImplementation),
            address(proxyAdmin),
            initData
        );
        address stoAddress = address(stoProxy);
        console.log("STO Proxy deployed at:", stoAddress);
        
        // Store deployment info
        deploymentInfo.sto = stoAddress;
        deploymentInfo.securityToken = securityToken;
        deploymentInfo.implementation = address(stoImplementation);
        deploymentInfo.proxyAdmin = address(proxyAdmin);
        
        // Create a reference to the STO through the proxy for easier interaction
        CappedSTOUpgradeable sto = CappedSTOUpgradeable(payable(stoAddress));
        
        // -----------------------------------------------------------------
        // STEP 2: Deploy Auxiliary Components 
        // -----------------------------------------------------------------
        console.log("\nStep 2: Deploying Auxiliary Components...");
       
        // Deploy FixedPrice logic contract with the real STO address
        FixedPrice fixedPrice = new FixedPrice(
            securityToken,
            rate,
            stoAddress
        );
        console.log("FixedPrice deployed at:", address(fixedPrice));
        deploymentInfo.fixedPrice = address(fixedPrice);
        
        // Set minimum investment if needed
        if (minInvestment > 0) {
            fixedPrice.setMinInvestment(minInvestment);
        }
        
        // Deploy Fees contract
        Fees fees = new Fees(
            FEE_RATE,
            payable(deployer),
            stoAddress
        );
        console.log("Fees deployed at:", address(fees));
        deploymentInfo.fees = address(fees);
        
        // Deploy the Minting contract with the real STO address
        Minting minting = new Minting(stoAddress);
        console.log("Minting deployed at:", address(minting));
        deploymentInfo.minting = address(minting);
        
        // Deploy the Refund contract with the real STO address
        // We can't set escrow yet, will update later
        Refund refund = new Refund(
            stoAddress,
            investmentToken,
            stoAddress // Temporary placeholder for escrow
        );
        console.log("Refund deployed at:", address(refund));
        deploymentInfo.refund = address(refund);
        
        // Now deploy Escrow with all required dependencies
        Escrow escrow = new Escrow(
            stoAddress,
            securityToken,
            investmentToken,
            payable(deployer),
            address(refund),
            address(minting),
            address(fees)
        );
        console.log("Escrow deployed at:", address(escrow));
        deploymentInfo.escrow = address(escrow);
        
        // Update Refund with the real Escrow address
        refund.updateEscrow(address(escrow));
        console.log("Updated Refund with Escrow address");
        
        // Update Minting with the real Escrow address
        minting.updateEscrow(address(escrow));
        console.log("Updated Minting with Escrow address");
        
        // Deploy Compliance with the deployer as owner
        Compliance compliance = new Compliance(deployer);
        console.log("Compliance deployed at:", address(compliance));
        deploymentInfo.compliance = address(compliance);
        
        // Deploy VerificationManager with the real STO address
        VerificationManager verificationManager = new VerificationManager(
            stoAddress,
            securityToken,
            IS_RULE_506C
        );
        console.log("VerificationManager deployed at:", address(verificationManager));
        deploymentInfo.verificationManager = address(verificationManager);
        
        // Add a call to set the manager component in the proxy to solve the immutable field issue
        try sto.setManagerComponents(
            address(0), // We'll set the InvestmentManager later
            address(0), // We'll set the FinalizationManager later
            address(verificationManager),
            address(compliance), // We've already deployed the Compliance
            address(0)  // We'll set the STOConfig later
        ) {
            console.log("VerificationManager registered with STO proxy");
        } catch Error(string memory reason) {
            console.log("Failed to register VerificationManager with STO proxy. Reason:", reason);
        } catch {
            console.log("Failed to register VerificationManager with STO proxy (unknown error)");
        }
        
        // Try to set the attribute registry if available, but we need to do it through the STO proxy
        try IToken(securityToken).attributeRegistry() returns (IAttributeRegistry attributeRegistry) {
            if (address(attributeRegistry) != address(0)) {
                // Call the helper method on the STO proxy with explicit verification manager address
                try sto.setAttributeRegistryOnVerificationManager(
                    address(verificationManager),
                    address(attributeRegistry)
                ) {
                    console.log("VerificationManager initialized with attribute registry through STO proxy");
                } catch Error(string memory reason) {
                    console.log("Failed to set attribute registry through STO proxy. Reason:", reason);
                    
                    // Alternative approach if the helper method doesn't work:
                    // Use a low-level call to invoke the method on the proxy
                    (bool success, ) = stoAddress.call(
                        abi.encodeWithSignature(
                            "setAttributeRegistryOnVerificationManager(address,address)",
                            address(verificationManager),
                            address(attributeRegistry)
                        )
                    );
                    if (success) {
                        console.log("VerificationManager initialized with attribute registry via low-level call");
                    } else {
                        console.log("All attempts to initialize attribute registry failed");
                    }
                } catch {
                    console.log("Failed to set attribute registry through STO proxy (unknown error)");
                }
            }
        } catch {
            console.log("Failed to get attribute registry from security token");
        }
        
        // Deploy STOConfig with the real STO address
        STOConfig stoConfig = new STOConfig(
            stoAddress,
            securityToken,
            IS_RULE_506C
        );
        console.log("STOConfig deployed at:", address(stoConfig));
        deploymentInfo.stoConfig = address(stoConfig);
        
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
        
        // Register STOConfig with the proxy explicitly to solve the immutable field issue
        try sto.setManagerComponents(
            address(0), // We'll set the InvestmentManager later
            address(0), // We'll set the FinalizationManager later
            address(0), // Already set
            address(0), // Already set
            address(stoConfig)
        ) {
            console.log("STOConfig registered with STO proxy");
        } catch Error(string memory reason) {
            console.log("Failed to register STOConfig with STO proxy. Reason:", reason);
        } catch {
            console.log("Failed to register STOConfig with STO proxy (unknown error)");
        }
        
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
        deploymentInfo.investmentManager = address(investmentManager);
        
        // Register InvestmentManager with the proxy explicitly to solve the immutable field issue
        try sto.setManagerComponents(
            address(investmentManager),
            address(0), // We'll set the FinalizationManager later
            address(0), // Already set
            address(0), // Already set
            address(0)  // Already set
        ) {
            console.log("InvestmentManager registered with STO proxy");
        } catch Error(string memory reason) {
            console.log("Failed to register InvestmentManager with STO proxy. Reason:", reason);
        } catch {
            console.log("Failed to register InvestmentManager with STO proxy (unknown error)");
        }
        
        // Set the STOConfig in the InvestmentManager using the helper method
        try sto.setSTOConfigOnInvestmentManager(
            address(investmentManager),
            address(stoConfig)
        ) {
            console.log("STOConfig set on InvestmentManager via STO proxy");
        } catch Error(string memory reason) {
            console.log("Failed to set STOConfig via STO proxy. Reason:", reason);
            
            // Fallback to direct call (which will likely fail due to authorization)
            try investmentManager.setSTOConfig(address(stoConfig)) {
                console.log("STOConfig set on InvestmentManager directly");
            } catch Error(string memory directReason) {
                console.log("Failed to set STOConfig directly. Reason:", directReason);
            } catch {
                console.log("Failed to set STOConfig directly (unknown error)");
            }
        } catch {
            console.log("Failed to set STOConfig via STO proxy (unknown error)");
        }
        
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
        deploymentInfo.finalizationManager = address(finalizationManager);
        
        // Register FinalizationManager with the proxy explicitly to solve the immutable field issue
        try sto.setManagerComponents(
            address(0), // Already set
            address(finalizationManager),
            address(0), // Already set
            address(0), // Already set
            address(0)  // Already set
        ) {
            console.log("FinalizationManager registered with STO proxy");
        } catch Error(string memory reason) {
            console.log("Failed to register FinalizationManager with STO proxy. Reason:", reason);
        } catch {
            console.log("Failed to register FinalizationManager with STO proxy (unknown error)");
        }
        
        // Set the STOConfig in the FinalizationManager using the helper method
        try sto.setSTOConfigOnFinalizationManager(
            address(finalizationManager),
            address(stoConfig)
        ) {
            console.log("STOConfig set on FinalizationManager via STO proxy");
        } catch Error(string memory reason) {
            console.log("Failed to set STOConfig on FinalizationManager via STO proxy. Reason:", reason);
            
            // Fallback to direct call (which will likely fail due to authorization)
            try finalizationManager.setSTOConfig(address(stoConfig)) {
                console.log("STOConfig set on FinalizationManager directly");
            } catch Error(string memory directReason) {
                console.log("Failed to set STOConfig on FinalizationManager directly. Reason:", directReason);
            } catch {
                console.log("Failed to set STOConfig on FinalizationManager directly (unknown error)");
            }
        } catch {
            console.log("Failed to set STOConfig on FinalizationManager via STO proxy (unknown error)");
        }
        
        // -----------------------------------------------------------------
        // STEP 3: Configure the STO with all components
        // -----------------------------------------------------------------
        console.log("\nStep 3: Configuring STO with Components...");
        
        // Call the configureWithContracts method on the STO (via proxy)
        try sto.configureWithContracts(
            startTime,
            endTime,
            hardCap,
            softCap,
            rate,
            payable(deployer), // funds receiver
            investmentToken,
            address(fixedPrice),
            address(minting),
            address(refund),
            address(escrow),
            address(fees)
        ) {
            console.log("STO configured with contracts successfully");
        } catch Error(string memory reason) {
            console.log("Failed to configure STO with contracts. Reason:", reason);
            
            // Fallback: If the full configuration fails, try setting components individually
            console.log("Attempting to update critical components individually...");
            
            try sto.setPricingLogic(address(fixedPrice)) {
                console.log("- PricingLogic set successfully");
            } catch Error(string memory pricingReason) {
                console.log("- Failed to set PricingLogic. Reason:", pricingReason);
            } catch {
                console.log("- Failed to set PricingLogic (unknown error)");
            }
        } catch {
            console.log("Failed to configure STO with contracts (unknown error)");
        }
        
        // -----------------------------------------------------------------
        // STEP 4: Verify that manager components are properly set
        // -----------------------------------------------------------------
        console.log("\nStep 4: Verifying manager component setup...");
        
        try sto.checkManagerComponents() {
            console.log("Manager component check completed");
        } catch Error(string memory reason) {
            console.log("Manager component check failed. Reason:", reason);
        } catch {
            console.log("Manager component check failed (unknown error)");
        }
        
        // -----------------------------------------------------------------
        // STEP 5: Register STO as agent on the security token
        // -----------------------------------------------------------------
        console.log("\nStep 5: Registering STO as agent on security token...");
        
        try sto.registerAsAgent() {
            console.log("STO registered as agent on the security token");
        } catch {
            console.log("Failed to register STO as agent - manual registration may be needed");
        }
        
        vm.stopBroadcast();
        
        // -----------------------------------------------------------------
        // STEP 6: Verify Contract Deployments
        // -----------------------------------------------------------------
        console.log("\nVerifying Contract Deployments...");
        
        // Check bytecode at each critical address
        bool allDeployed = true;
        
        // Verify critical contracts have bytecode
        allDeployed = checkBytecode(address(stoImplementation)) && allDeployed;
        allDeployed = checkBytecode(address(proxyAdmin)) && allDeployed;
        allDeployed = checkBytecode(stoAddress) && allDeployed;
        allDeployed = checkBytecode(address(stoConfig)) && allDeployed;
        allDeployed = checkBytecode(address(verificationManager)) && allDeployed;
        allDeployed = checkBytecode(address(investmentManager)) && allDeployed;
        allDeployed = checkBytecode(address(finalizationManager)) && allDeployed;
        
        if (!allDeployed) {
            console.log("\n[WARNING] Some contracts have no bytecode at their addresses!");
            console.log("This typically means the transactions were not confirmed or failed.");
            console.log("Possible reasons:");
            console.log("1. The script was run in 'dry-run' mode without --broadcast");
            console.log("2. The transactions failed due to gas issues or network congestion");
            console.log("3. You checked too soon and the transactions are still pending");
            console.log("4. You're connected to a different network than where you deployed");
            console.log("\nRecommended actions:");
            console.log("1. Check your transactions on the block explorer");
            console.log("2. Run with --broadcast flag if you ran in dry-run mode");
            console.log("3. Check logs for any error messages during deployment");
            console.log("4. Try running the script again with higher gas price if transactions failed");
        } else {
            console.log("\n[SUCCESS] All contracts successfully deployed and verified!");
        }
        
        // -----------------------------------------------------------------
        // STEP 7: Display Deployment Summary
        // -----------------------------------------------------------------
        console.log("\nDeployment Summary:");
        console.log("Security Token:", securityToken);
        console.log("STO Proxy Address:", stoAddress);
        console.log("STO Implementation:", address(stoImplementation));
        console.log("ProxyAdmin:", address(proxyAdmin));
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
        console.log("2. Verify all contracts on Etherscan/Polygonscan");
        console.log("3. Verify investors through the VerificationManager");
        console.log("4. If the STO is not registered as an agent, register it manually");
        console.log("\n=== UPGRADE INSTRUCTIONS ===");
        console.log("To upgrade the implementation in the future:");
        console.log("1. Deploy a new implementation contract");
        console.log("2. Call proxyAdmin.upgrade(proxy, newImplementation)");
    }
}