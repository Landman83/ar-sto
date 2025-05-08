// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./CappedSTO.sol";
import "./interfaces/ISTOConfig.sol";
import "./interfaces/IFinalizationManager.sol";
import "./interfaces/IInvestmentManager.sol";
import "./interfaces/IVerificationManager.sol";

/**
 * @title CappedSTOUpgradeable
 * @notice Extension of CappedSTO that adds proper initialization for OpenZeppelin's transparent proxy pattern
 * @dev This contract adds an initialize function that can be called via delegatecall from a proxy
 *      to properly set up the contract state. It extends the base CappedSTO contract but adds
 *      proxy-compatible initialization.
 */
contract CappedSTOUpgradeable is CappedSTO {
    // Events for configuration tracking
    event ConfigurationError(string reason);
    event ConfigurationSuccess(string message);
    event ConfigurationStatus(string component, string status);
    
    // Flag to prevent re-initialization
    bool private _initialized;
    
    /**
     * @dev Constructor that delegates to the base contract
     * @notice This constructor is only used for the implementation contract and 
     *         is not used when deployed behind a proxy
     */
    constructor(
        address _securityToken,
        bool _isRule506c, 
        address _investmentToken,
        address _escrow,
        address _refund,
        address _minting,
        address _pricingLogic,
        address _fees,
        address _investmentManager,
        address _finalizationManager,
        address _verificationManager,
        address _compliance,
        address _stoConfig
    ) CappedSTO(
        _securityToken,
        _isRule506c,
        _investmentToken,
        _escrow,
        _refund,
        _minting,
        _pricingLogic,
        _fees,
        _investmentManager,
        _finalizationManager,
        _verificationManager,
        _compliance,
        _stoConfig
    ) {}
    
    /**
     * @notice Initialization function to replace constructor logic
     * @dev This function can only be called once and is meant to be called by the proxy
     * @param _securityToken Address of the security token
     * @param _isRule506c Flag indicating if this is a Rule506c offering
     * @param _owner Address that will own the STO
     */
    function initialize(
        address _securityToken,
        bool _isRule506c,
        address _owner
    ) external {
        // Prevent re-initialization
        require(!_initialized, "CappedSTOUpgradeable: already initialized");
        _initialized = true;
        
        // Set basic properties
        // Note: Many properties are set in the constructor of the base contract,
        // but for a proper upgradeable contract, all state should be initialized here
        securityToken = _securityToken;
        isRule506cOffering = _isRule506c;
        
        // Set up owner and roles 
        // Since Ownable doesn't have a proper initialize function, we need to handle ownership
        // transfer here manually (this depends on the Ownable implementation)
        _transferOwnership(_owner);
        
        // Set up basic roles
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(OPERATOR_ROLE, _owner);
        _grantRole(FACTORY_ROLE, _owner);
    }
    
    /**
     * @notice Helper function to check if manager components are accessible
     * @return A flag indicating if all components are accessible
     */
    function checkManagerComponents() external returns (bool) {
        bool allAccessible = true;
        string memory status = "";
        
        // Check STOConfig
        if (address(stoConfig) == address(0)) {
            status = "STOConfig is not set";
            allAccessible = false;
        } else {
            try stoConfig.rate() returns (uint256) {
                status = "STOConfig is accessible";
            } catch {
                status = "STOConfig is inaccessible";
                allAccessible = false;
            }
        }
        emit ConfigurationStatus("STOConfig", status);
        
        // Check InvestmentManager
        if (address(investmentManager) == address(0)) {
            status = "InvestmentManager is not set";
            allAccessible = false;
        } else {
            try investmentManager.allowBeneficialInvestments() returns (bool) {
                status = "InvestmentManager is accessible";
            } catch {
                status = "InvestmentManager is inaccessible";
                allAccessible = false;
            }
        }
        emit ConfigurationStatus("InvestmentManager", status);
        
        // Check FinalizationManager
        if (address(finalizationManager) == address(0)) {
            status = "FinalizationManager is not set";
            allAccessible = false;
        } else {
            try finalizationManager.isFinalized() returns (bool) {
                status = "FinalizationManager is accessible";
            } catch {
                status = "FinalizationManager is inaccessible";
                allAccessible = false;
            }
        }
        emit ConfigurationStatus("FinalizationManager", status);
        
        // Check VerificationManager
        if (address(verificationManager) == address(0)) {
            status = "VerificationManager is not set";
            allAccessible = false;
        } else {
            try verificationManager.isInvestorVerified(address(this)) returns (bool) {
                status = "VerificationManager is accessible";
            } catch {
                status = "VerificationManager is inaccessible";
                allAccessible = false;
            }
        }
        emit ConfigurationStatus("VerificationManager", status);
        
        return allAccessible;
    }
    
    /**
     * @notice Set manager components in the upgradeable contract
     * @dev Since we inherit from CappedSTO which has immutable manager components,
     *      this function allows us to "override" them for the proxy instance
     * @param _investmentManager Address of the investment manager
     * @param _finalizationManager Address of the finalization manager
     * @param _verificationManager Address of the verification manager
     * @param _compliance Address of the compliance contract
     * @param _stoConfig Address of the STO configuration
     */
    function setManagerComponents(
        address _investmentManager,
        address _finalizationManager,
        address _verificationManager,
        address _compliance,
        address _stoConfig
    ) external {
        require(
            owner() == msg.sender || hasRole(FACTORY_ROLE, msg.sender),
            "CappedSTOUpgradeable: caller is not the owner or factory"
        );
        
        if (_investmentManager != address(0)) {
            investmentManager = InvestmentManager(_investmentManager);
            emit ConfigurationSuccess("InvestmentManager set");
        }
        
        if (_finalizationManager != address(0)) {
            finalizationManager = FinalizationManager(_finalizationManager);
            emit ConfigurationSuccess("FinalizationManager set");
        }
        
        if (_verificationManager != address(0)) {
            verificationManager = IVerificationManager(_verificationManager);
            emit ConfigurationSuccess("VerificationManager set");
        }
        
        if (_compliance != address(0)) {
            compliance = ICompliance(_compliance);
            emit ConfigurationSuccess("Compliance set");
        }
        
        if (_stoConfig != address(0)) {
            stoConfig = ISTOConfig(_stoConfig);
            emit ConfigurationSuccess("STOConfig set");
        }
    }

    /**
     * @notice Configure the STO with all contract dependencies
     * @dev This method is called after initialization to connect all the components
     * @param _startTime Start time of the STO
     * @param _endTime End time of the STO
     * @param _hardCap Hard cap of the STO
     * @param _softCap Soft cap of the STO
     * @param _rate Token rate
     * @param _fundsReceiver Address to receive funds
     * @param _investmentToken Token used for investments
     * @param _pricingLogic Pricing logic contract
     * @param _minting Minting contract
     * @param _refund Refund contract
     * @param _escrow Escrow contract
     * @param _fees Fees contract
     */
    function configureWithContracts(
        uint256 _startTime,
        uint256 _endTime,
        uint256 _hardCap,
        uint256 _softCap,
        uint256 _rate,
        address payable _fundsReceiver,
        address _investmentToken,
        address _pricingLogic,
        address _minting,
        address _refund,
        address _escrow,
        address _fees
    ) external {
        // Only allow the owner or a contract with FACTORY_ROLE to configure
        require(
            owner() == msg.sender || hasRole(FACTORY_ROLE, msg.sender),
            "CappedSTOUpgradeable: caller is not the owner or factory"
        );
        
        // Validate all addresses
        require(_investmentToken != address(0), "Investment token cannot be zero");
        require(_pricingLogic != address(0), "Pricing logic cannot be zero");
        require(_minting != address(0), "Minting cannot be zero");
        require(_refund != address(0), "Refund cannot be zero");
        require(_escrow != address(0), "Escrow cannot be zero");
        require(_fundsReceiver != address(0), "Funds receiver cannot be zero");
        
        // Set core properties
        investmentToken = IERC20(_investmentToken);
        pricingLogic = PricingLogic(_pricingLogic);
        minting = Minting(_minting);
        refund = Refund(_refund);
        escrow = Escrow(_escrow);
        
        // Set fees contract if provided
        if (_fees != address(0)) {
            fees = IFees(_fees);
        }
        
        // Initialize the Cap contract directly with the new values
        _initialize(_hardCap, _softCap);
        
        // Directly configure STOConfig without calling setCaps
        if (address(stoConfig) != address(0)) {
            // Call the configure method directly on STOConfig
            try ISTOConfig(address(stoConfig)).configure(
                _startTime,
                _endTime,
                _hardCap,
                _softCap,
                _rate,
                _fundsReceiver,
                _investmentToken
            ) {
                emit ConfigurationSuccess("STOConfig configured successfully");
            } catch Error(string memory reason) {
                emit ConfigurationError(reason);
            } catch {
                emit ConfigurationError("Failed to configure STOConfig");
            }
        } else {
            emit ConfigurationError("STOConfig is not set");
            
            // You can attempt to recreate the STOConfig if it's missing
            // This is an optional step and depends on your deployment requirements
            // createSTOConfig(_startTime, _endTime, _hardCap, _softCap, _rate, _fundsReceiver, _investmentToken);
        }
    }
    
    /**
     * @notice Set the caps for the STO
     * @param _hardCap Hard cap in tokens
     * @param _softCap Soft cap in tokens 
     * @param _rate Conversion rate
     * @param _wallet Address to receive funds
     */
    function setCaps(
        uint256 _hardCap,
        uint256 _softCap,
        uint256 _rate,
        address payable _wallet
    ) public {
        // Only allow the owner or a contract with FACTORY_ROLE to configure
        require(
            owner() == msg.sender || hasRole(FACTORY_ROLE, msg.sender),
            "CappedSTOUpgradeable: caller is not the owner or factory"
        );
        
        // Since we don't have direct access to these variables in the parent contracts,
        // we need to either:
        // 1. Call existing setter methods if they exist
        // 2. Store these values in this contract and override the getters
        
        // Check if stoConfig is set correctly
        if (address(stoConfig) == address(0)) {
            emit ConfigurationError("STOConfig is not set properly");
            return;
        }
        
        // Get the current times from STOConfig or use safe defaults
        uint256 currentStartTime;
        uint256 currentEndTime;
        
        // Safely get current values, using try/catch to handle possible failures
        try ISTOConfig(address(stoConfig)).startTime() returns (uint256 startTime) {
            currentStartTime = startTime;
        } catch {
            // If call fails, use a reasonable default
            currentStartTime = block.timestamp + 60; // 1 minute from now
            emit ConfigurationError("Failed to get startTime from STOConfig, using default");
        }
        
        try ISTOConfig(address(stoConfig)).endTime() returns (uint256 endTime) {
            currentEndTime = endTime;
        } catch {
            // If call fails, use a reasonable default
            currentEndTime = block.timestamp + 3600; // 1 hour from now
            emit ConfigurationError("Failed to get endTime from STOConfig, using default");
        }
        
        // Now configure with our safely obtained values
        try ISTOConfig(address(stoConfig)).configure(
            currentStartTime, // Use safely obtained start time
            currentEndTime,   // Use safely obtained end time
            _hardCap,
            _softCap,
            _rate,
            _wallet,
            address(investmentToken)
        ) {
            // Configuration successful
            emit ConfigurationSuccess("STOConfig configured successfully");
        } catch {
            // If the call fails (e.g., stoConfig method doesn't exist)
            emit ConfigurationError("Failed to configure STOConfig");
        }
    }
    
    // Events already declared at the top of the contract
    
    /**
     * @notice Helper function to set attribute registry on a verification manager
     * @dev This allows the verification manager's access control to be satisfied
     * @param _verificationManager Address of the verification manager to use
     * @param _attributeRegistry Address of the attribute registry to set
     */
    function setAttributeRegistryOnVerificationManager(
        address _verificationManager,
        address _attributeRegistry
    ) external {
        // Only allow the owner or a contract with FACTORY_ROLE to call
        require(
            owner() == msg.sender || hasRole(FACTORY_ROLE, msg.sender),
            "CappedSTOUpgradeable: caller is not the owner or factory"
        );
        
        // Call the verification manager's method directly using the passed address
        // instead of relying on the immutable field
        IVerificationManager(_verificationManager).setAttributeRegistry(_attributeRegistry);
    }
    
    /**
     * @notice Helper function to set STOConfig on the investment manager
     * @dev This allows the investment manager's access control to be satisfied
     * @param _investmentManager Address of the investment manager
     * @param _stoConfig Address of the STOConfig to set
     */
    function setSTOConfigOnInvestmentManager(
        address _investmentManager, 
        address _stoConfig
    ) external {
        // Only allow the owner or a contract with FACTORY_ROLE to call
        require(
            owner() == msg.sender || hasRole(FACTORY_ROLE, msg.sender),
            "CappedSTOUpgradeable: caller is not the owner or factory"
        );
        
        // Call the investment manager's method
        IInvestmentManager(_investmentManager).setSTOConfig(_stoConfig);
    }
    
    /**
     * @notice Helper function to set STOConfig on the finalization manager
     * @dev This allows the finalization manager's access control to be satisfied
     * @param _finalizationManager Address of the finalization manager
     * @param _stoConfig Address of the STOConfig to set
     */
    function setSTOConfigOnFinalizationManager(
        address _finalizationManager, 
        address _stoConfig
    ) external {
        // Only allow the owner or a contract with FACTORY_ROLE to call
        require(
            owner() == msg.sender || hasRole(FACTORY_ROLE, msg.sender),
            "CappedSTOUpgradeable: caller is not the owner or factory"
        );
        
        // Call the finalization manager's method
        IFinalizationManager(_finalizationManager).setSTOConfig(_stoConfig);
    }
    
    // Storage gap for future upgrades
    uint256[50] private __gap;
}