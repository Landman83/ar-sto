// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import "forge-std/Script.sol";
import "../src/CappedSTO.sol";
import "../src/factory/STOFactory.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title Deploy STO Script
 * @notice Deploys a Security Token Offering (STO) using environment variables
 */
/*
contract DeploySTOScript is Script {
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

    // Deployment parameters from deploy-notes.txt
    bool private constant IS_RULE_506C = true;
    uint256 private constant START_TIME_BUFFER = 1 minutes; // Buffer to ensure start time is in the future
    uint256 private constant OFFERING_DURATION = 1 hours;
    uint256 private constant FEE_RATE = 200; // 2% fee (in basis points)

    function run() public {
        // Set up RPC connection directly from environment
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
        console.log("Start Time: current block timestamp");
        console.log("End Time: current block timestamp + 1 hour");
        console.log("Hard Cap:", hardCap);
        console.log("Soft Cap:", softCap);
        console.log("Rate:", rate);
        console.log("Funds Receiver:", deployer);
        console.log("Investment Token:", investmentToken);
        console.log("Fee Rate:", FEE_RATE);
        console.log("Fee Wallet:", deployer);
        console.log("Owner:", deployer);
        console.log("Min Investment:", minInvestment);

        // 1. Deploy STO implementation - we must use the real security token address
        // since the constructor has a check that prevents address(0)
        console.log("Deploying STO implementation with security token:", securityToken);
        CappedSTO stoImplementation = new CappedSTO(securityToken, IS_RULE_506C);
        console.log("STO implementation deployed at:", address(stoImplementation));

        // 2. Deploy STO factory
        STOFactory factory = new STOFactory(address(stoImplementation));
        console.log("STO factory deployed at:", address(factory));

        // 3. Calculate start and end times (with buffer to ensure start time is in the future)
        uint256 startTime = block.timestamp + START_TIME_BUFFER;
        uint256 endTime = startTime + OFFERING_DURATION; 
        console.log("Current timestamp:", block.timestamp);
        console.log("Actual start time:", startTime);
        console.log("Actual end time:", endTime);

        // 4. Deploy STO with factory
        (bytes32 deploymentId, address stoAddress) = factory.deploySTOWithParams(
            securityToken,                // _securityToken
            IS_RULE_506C,                 // _isRule506c (set to true for accredited investor checks)
            startTime,                    // _startTime (now)
            endTime,                      // _endTime (now + 1 hour)
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

        // 5. Log STO deployment details
        console.log("STO deployed successfully!");
        console.log("STO Address:", stoAddress);
        console.log("Deployment ID:", vm.toString(deploymentId));

        // 6. Get and log the auxiliary contract addresses
        STOFactory.STODeploymentInfo memory info = factory.getDeploymentInfo(deploymentId);
        console.log("Fixed Price Logic:", info.fixedPrice);
        console.log("Minting Contract:", info.minting);
        console.log("Refund Contract:", info.refund);
        console.log("Escrow Contract:", info.escrow);
        console.log("Fees Contract:", info.fees);

        // 7. Try to register STO as agent on the token (if needed)
        CappedSTO sto = CappedSTO(payable(stoAddress));
        try sto.registerAsAgent() {
            console.log("STO registered as agent on the security token");
        } catch {
            console.log("Could not register STO as agent - manual registration may be needed");
        }

        vm.stopBroadcast();
        
        // Final instructions
        console.log("");
        console.log("=== NEXT STEPS ===");
        console.log("1. The STO is now deployed and ready to accept investments");
        console.log("2. Verify the STO contract on Etherscan/Polygonscan");
        console.log("3. Verify investors through the STO's verification manager");
        console.log("4. If the STO is not registered as an agent, register it manually");
    }
}
*/