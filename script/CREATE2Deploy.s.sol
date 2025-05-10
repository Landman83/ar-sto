// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/CappedSTO.sol";
import "../src/factory/STOFactory.sol";
import "../src/utils/InvestmentManager.sol";
import "../src/utils/FinalizationManager.sol";
import "../src/utils/VerificationManager.sol";
import "../src/utils/STOConfig.sol";
import "../src/mixins/Compliance.sol";
import "../src/utils/Escrow.sol";
import "../src/utils/Refund.sol";
import "../src/utils/Minting.sol";
import "../src/mixins/FixedPrice.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Create2 as OZCreate2} from "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @title CREATE2 Deploy STO Script
 * @notice Deploys a Security Token Offering (STO) using CREATE2 for deterministic addresses
 * @dev This script follows the deployment-guide.txt and uses CREATE2 for all contract deployments
 */
/*
contract CREATE2DeployScript is Script {
    // Salt for CREATE2 deployment - can be modified to generate different addresses
    bytes32 public constant SALT = bytes32(uint256(0x12345));
    
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
    
    // Environment variables
    string private constant ENV_RPC_URL = "RPC_URL";
    string private constant ENV_CHAIN_ID = "CHAIN_ID";
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

    // Built-in Foundry CREATE2 factory address
    address constant FOUNDRY_CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    
    // CREATE2 deployment helper using Foundry's factory
    function deployContract(bytes memory bytecode, bytes32 salt) internal returns (address payable) {
        // Call the Foundry CREATE2 factory
        (bool success, bytes memory returnData) = FOUNDRY_CREATE2_FACTORY.call(
            abi.encodePacked(salt, bytecode)
        );
        require(success, "CREATE2 deployment failed");
        
        // Extract the deployed address from the returned data
        address deployedAddress;
        assembly {
            deployedAddress := mload(add(returnData, 20))
        }
        
        return payable(deployedAddress);
    }
    
    // Computes the deterministic address without deployment
    function computeAddress(bytes memory bytecode, bytes32 salt) internal view returns (address) {
        bytes32 bytecodeHash = keccak256(bytecode);
        bytes32 _data = keccak256(
            abi.encodePacked(bytes1(0xff), FOUNDRY_CREATE2_FACTORY, salt, bytecodeHash)
        );
        return address(uint160(uint256(_data)));
    }
    
    // Generate a unique salt for each contract
    function generateSalt(string memory contractName) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(SALT, contractName));
    }
    
    // External version of deployContract that can be called with try/catch
    function deployContractExternal(bytes memory bytecode, bytes32 salt) external returns (address) {
        return deployContract(bytecode, salt);
    }

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

        // Log connection and deployment parameters
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

        // -----------------------------------------------------------------
        // 1. Compute deterministic addresses (for circular dependencies)
        // -----------------------------------------------------------------
        
        // Calculate start and end times
        uint256 startTime = block.timestamp + START_TIME_BUFFER;
        uint256 endTime = startTime + OFFERING_DURATION; 
        console.log("Current timestamp:", block.timestamp);
        console.log("Actual start time:", startTime);
        console.log("Actual end time:", endTime);
        
        // We need to compute the STO address first, to provide it to other contracts
        bytes memory stoImplCreationCode = type(CappedSTO).creationCode;
        bytes memory stoImplArgs = abi.encode(securityToken, IS_RULE_506C);
        bytes memory stoImplBytecode = abi.encodePacked(stoImplCreationCode, stoImplArgs);
        bytes32 stoImplSalt = generateSalt("STOImplementation");
        
        address stoImplementationAddr = computeAddress(stoImplBytecode, stoImplSalt);
        console.log("Predicted STO Implementation Address:", stoImplementationAddr);
        
        // Compute the STO factory address
        bytes memory factoryCreationCode = type(STOFactory).creationCode;
        bytes memory factoryArgs = abi.encode(stoImplementationAddr);
        bytes memory factoryBytecode = abi.encodePacked(factoryCreationCode, factoryArgs);
        bytes32 factorySalt = generateSalt("STOFactory");
        
        address factoryAddr = computeAddress(factoryBytecode, factorySalt);
        console.log("Predicted STOFactory Address:", factoryAddr);

        // Compute a unique deployment ID for this specific deployment
        bytes32 deploymentId = keccak256(abi.encodePacked(
            deployer,
            securityToken,
            investmentToken,
            block.timestamp
        ));
        
        // STOProxy doesn't have predictable address with factory, so we'll store it later
        address stoProxyAddr;
        
        // -----------------------------------------------------------------
        // 2. Deploy all contracts using CREATE2
        // -----------------------------------------------------------------
        
        // Deploy STO implementation with CREATE2
        console.log("Attempting to deploy STO implementation...");
        address payable stoImplDeployed;
        try this.deployContractExternal(stoImplBytecode, stoImplSalt) returns (address addr) {
            stoImplDeployed = payable(addr);
            console.log("STO Implementation Deployed at:", stoImplDeployed);
            require(stoImplDeployed == stoImplementationAddr, "STO implementation address mismatch");
        } catch Error(string memory reason) {
            console.log("CREATE2 deployment failed with reason:", reason);
            console.log("Falling back to regular deployment...");
            
            // Create mock addresses for required parameters
            address mockEscrow = address(0x1111);
            address mockRefund = address(0x2222);
            address mockMinting = address(0x3333);
            address mockPricingLogic = address(0x4444);
            address mockFees = address(0x5555);
            address mockInvestmentManager = address(0x6666);
            address mockFinalizationManager = address(0x7777);
            address mockVerificationManager = address(0x8888);
            address mockCompliance = address(0x9999);
            address mockSTOConfig = address(0xAAAA);
            
            // Log the parameters we're using
            console.log("Using real securityToken:", securityToken);
            console.log("Using real investmentToken:", investmentToken);
            
            // Deploy using new directly with more detailed error trapping
            try new CappedSTO(
                securityToken,
                IS_RULE_506C,
                investmentToken,
                mockEscrow,
                mockRefund,
                mockMinting,
                mockPricingLogic,
                mockFees,
                mockInvestmentManager,
                mockFinalizationManager,
                mockVerificationManager,
                mockCompliance,
                mockSTOConfig
            ) returns (CappedSTO stoImpl) {
                stoImplDeployed = payable(address(stoImpl));
                console.log("STO Implementation Deployed with fallback at:", stoImplDeployed);
                stoImplementationAddr = stoImplDeployed; // Update the expected address
            } catch Error(string memory reason) {
                console.log("Regular deployment failed with reason:", reason);
                revert(string.concat("Regular deployment failed: ", reason));
            } catch {
                console.log("Regular deployment failed with unknown error");
                revert("Regular deployment failed: unknown error");
            }
        } catch {
            console.log("STO implementation deployment failed with unknown error");
            console.log("Falling back to regular deployment...");
            
            // Create mock addresses for required parameters
            address mockEscrow = address(0x1111);
            address mockRefund = address(0x2222);
            address mockMinting = address(0x3333);
            address mockPricingLogic = address(0x4444);
            address mockFees = address(0x5555);
            address mockInvestmentManager = address(0x6666);
            address mockFinalizationManager = address(0x7777);
            address mockVerificationManager = address(0x8888);
            address mockCompliance = address(0x9999);
            address mockSTOConfig = address(0xAAAA);
            
            // Log the parameters we're using
            console.log("Using real securityToken:", securityToken);
            console.log("Using real investmentToken:", investmentToken);
            
            // Deploy using new directly with more detailed error trapping
            try new CappedSTO(
                securityToken,
                IS_RULE_506C,
                investmentToken,
                mockEscrow,
                mockRefund,
                mockMinting,
                mockPricingLogic,
                mockFees,
                mockInvestmentManager,
                mockFinalizationManager,
                mockVerificationManager,
                mockCompliance,
                mockSTOConfig
            ) returns (CappedSTO stoImpl) {
                stoImplDeployed = payable(address(stoImpl));
                console.log("STO Implementation Deployed with fallback at:", stoImplDeployed);
                stoImplementationAddr = stoImplDeployed; // Update the expected address
            } catch Error(string memory reason) {
                console.log("Regular deployment failed with reason:", reason);
                revert(string.concat("Regular deployment failed: ", reason));
            } catch {
                console.log("Regular deployment failed with unknown error");
                revert("Regular deployment failed: unknown error");
            }
        }
        
        // Deploy STO factory with CREATE2
        console.log("Attempting to deploy STOFactory...");
        address payable factoryDeployed;
        try this.deployContractExternal(factoryBytecode, factorySalt) returns (address addr) {
            factoryDeployed = payable(addr);
            console.log("STOFactory Deployed at:", factoryDeployed);
            require(factoryDeployed == factoryAddr, "STOFactory address mismatch");
        } catch Error(string memory reason) {
            console.log("CREATE2 factory deployment failed with reason:", reason);
            console.log("Falling back to regular deployment...");
            
            // Log the STO implementation address we're using
            console.log("Using STO implementation address:", stoImplementationAddr);
            
            // Deploy using regular new operator with better error trapping
            try new STOFactory(stoImplementationAddr) returns (STOFactory factory) {
                factoryDeployed = payable(address(factory));
                console.log("STOFactory Deployed with fallback at:", factoryDeployed);
                factoryAddr = factoryDeployed; // Update the expected address
            } catch Error(string memory reason) {
                console.log("Regular factory deployment failed with reason:", reason);
                revert(string.concat("Regular factory deployment failed: ", reason));
            } catch {
                console.log("Regular factory deployment failed with unknown error");
                revert("Regular factory deployment failed with unknown error");
            }
        } catch {
            console.log("STOFactory deployment failed with unknown error");
            console.log("Falling back to regular deployment...");
            
            // Log the STO implementation address we're using
            console.log("Using STO implementation address:", stoImplementationAddr);
            
            // Deploy using regular new operator with better error trapping
            try new STOFactory(stoImplementationAddr) returns (STOFactory factory) {
                factoryDeployed = payable(address(factory));
                console.log("STOFactory Deployed with fallback at:", factoryDeployed);
                factoryAddr = factoryDeployed; // Update the expected address
            } catch Error(string memory reason) {
                console.log("Regular factory deployment failed with reason:", reason);
                revert(string.concat("Regular factory deployment failed: ", reason));
            } catch {
                console.log("Regular factory deployment failed with unknown error");
                revert("Regular factory deployment failed with unknown error");
            }
        }
        
        // Deploy STO with factory
        STOFactory factory = STOFactory(factoryAddr);
        (bytes32 actualDeploymentId, address stoAddress) = factory.deploySTOWithParams(
            securityToken,            // _securityToken
            IS_RULE_506C,             // _isRule506c
            startTime,                // _startTime
            endTime,                  // _endTime
            hardCap,                  // _hardCap
            softCap,                  // _softCap
            rate,                     // _rate
            payable(deployer),        // _fundsReceiver
            investmentToken,          // _investmentToken
            FEE_RATE,                 // _feeRate
            deployer,                 // _feeWallet
            deployer,                 // _owner
            minInvestment             // _minInvestment
        );
        
        stoProxyAddr = stoAddress;
        console.log("STO Proxy Deployed at:", stoProxyAddr);
        console.log("Deployment ID:", vm.toString(actualDeploymentId));
        
        // -----------------------------------------------------------------
        // 3. Get and log contract addresses
        // -----------------------------------------------------------------
        
        // Get deployed auxiliary contract addresses from the factory
        STOFactory.STODeploymentInfo memory info = factory.getDeploymentInfo(actualDeploymentId);
        console.log("");
        console.log("Auxiliary Contract Addresses:");
        console.log("Fixed Price Logic:", info.fixedPrice);
        console.log("Minting Contract:", info.minting);
        console.log("Refund Contract:", info.refund);
        console.log("Escrow Contract:", info.escrow);
        console.log("Fees Contract:", info.fees);
        
        // -----------------------------------------------------------------
        // 4. Final setup: register STO as agent on the token
        // -----------------------------------------------------------------
        
        CappedSTO sto = CappedSTO(payable(stoProxyAddr));
        try sto.registerAsAgent() {
            console.log("STO registered as agent on the security token");
        } catch {
            console.log("Could not register STO as agent - manual registration may be needed");
        }

        vm.stopBroadcast();
        
        // -----------------------------------------------------------------
        // 5. Output additional information
        // -----------------------------------------------------------------
        
        console.log("");
        console.log("CREATE2 Deployment Summary:");
        console.log("- All contracts were deployed with deterministic addresses using CREATE2");
        console.log("- The factory pattern was used to properly initialize contracts with circular dependencies");
        console.log("- Change the SALT constant at the top of this script to generate different addresses");
        
        console.log("");
        console.log("=== NEXT STEPS ===");
        console.log("1. The STO is now deployed and ready to accept investments");
        console.log("2. Verify the STO contract on Etherscan/Polygonscan");
        console.log("3. Verify investors through the STO's verification manager");
        console.log("4. If the STO is not registered as an agent, register it manually");
        console.log("");
        console.log("For changes to the deployment addresses:");
        console.log("- Modify the SALT constant at the top of the script");
        console.log("- You can use a different salt for each deployed contract");
    }
}
*/