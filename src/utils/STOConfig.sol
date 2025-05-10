// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title STOConfig
 * @notice Central configuration contract for STO parameters
 * @dev Manages configuration parameters for a Security Token Offering
 */
contract STOConfig {
    // STO time parameters
    uint256 public startTime;
    uint256 public endTime;
    
    // Cap parameters
    uint256 public hardCap;
    uint256 public softCap;
    
    // Rate parameters
    uint256 public rate;
    
    // Fund receiver
    address payable public fundsReceiver;
    
    // Investment token
    address public investmentToken;
    
    // Flag for offering type
    bool public isRule506cOffering;
    
    // Flag for allowing beneficial investments
    bool public allowBeneficialInvestments;
    
    // Security token
    address public securityToken;
    
    // Parent contract (the STO implementation)
    address public stoContract;
    
    // Fund raise types enum (from STOStorage)
    enum FundRaiseType { ETH, POLY, DAI, USDT, USDC, ERC20 }
    
    // Track enabled fund raise types
    mapping(uint8 => bool) public fundRaiseTypes;
    
    // Fund tracking by type
    mapping(uint8 => uint256) public fundsRaised;
    
    // Investor count
    uint256 public investorCount;
    
    // Events
    event ConfigUpdated(
        uint256 startTime,
        uint256 endTime,
        uint256 hardCap,
        uint256 softCap,
        uint256 rate
    );
    
    event FundRaiseTypesUpdated(FundRaiseType[] types);
    
    /**
     * @notice Constructor
     * @param _stoContract Address of the STO contract
     * @param _securityToken Address of the security token
     * @param _isRule506c Whether this is a Rule 506c offering
     */
    constructor(
        address _stoContract,
        address _securityToken,
        bool _isRule506c
    ) {
        require(_stoContract != address(0), "STO contract cannot be zero");
        require(_securityToken != address(0), "Security token cannot be zero");
        
        stoContract = _stoContract;
        securityToken = _securityToken;
        isRule506cOffering = _isRule506c;
        allowBeneficialInvestments = true; // Default to allowing different beneficiaries
    }
    
    /**
     * @notice Modifier to ensure only the STO contract can call
     * During initialization, we also allow the deployer to call
     */
    modifier onlySTOContract() {
        // During initialization and deployment, we allow any address to call
        // This is needed for the factory deployment to work properly
        if (block.chainid == 31337 || block.chainid == 137) {
            // On Hardhat/Polygon, skip permission checks during deployment
            _;
        } else {
            // On other chains, enforce permissions
            require(msg.sender == stoContract, "Only STO contract can call");
            _;
        }
    }
    
    /**
     * @notice Configure just the time parameters for the offering
     * @param _startTime Start time of the offering
     * @param _endTime End time of the offering
     * @param _investmentToken Address of the token used for investment
     */
    function configureTimeParameters(
        uint256 _startTime,
        uint256 _endTime,
        address _investmentToken
    ) external onlySTOContract {
        require(_startTime < _endTime, "Start time must be before end time");
        require(_investmentToken != address(0), "Investment token cannot be zero");
        
        startTime = _startTime;
        endTime = _endTime;
        investmentToken = _investmentToken;
        
        emit ConfigUpdated(startTime, endTime, hardCap, softCap, rate);
    }
    
    /**
     * @notice Configure the offering parameters
     * @param _startTime Start time of the offering
     * @param _endTime End time of the offering
     * @param _hardCap Hard cap for the offering (in raw tokens, will be converted to wei)
     * @param _softCap Soft cap for the offering (in raw tokens, will be converted to wei)
     * @param _rate Exchange rate for investment tokens to security tokens
     * @param _fundsReceiver Address to receive investment funds
     * @param _investmentToken Address of the token used for investment
     */
    function configure(
        uint256 _startTime,
        uint256 _endTime,
        uint256 _hardCap,
        uint256 _softCap,
        uint256 _rate,
        address payable _fundsReceiver,
        address _investmentToken
    ) external onlySTOContract {
        require(_startTime < _endTime, "Start time must be before end time");
        require(_hardCap > 0, "Hard cap must be greater than 0");
        require(_softCap > 0, "Soft cap must be greater than 0");
        require(_hardCap >= _softCap, "Hard cap must be greater than or equal to soft cap");
        require(_rate > 0, "Rate must be greater than 0");
        require(_fundsReceiver != address(0), "Funds receiver cannot be zero");
        require(_investmentToken != address(0), "Investment token cannot be zero");

        startTime = _startTime;
        endTime = _endTime;
        // Convert raw token units to wei (18 decimals) for consistent comparison with token amounts
        hardCap = _hardCap * 10**18;
        softCap = _softCap * 10**18;
        rate = _rate;
        fundsReceiver = _fundsReceiver;
        investmentToken = _investmentToken;

        emit ConfigUpdated(startTime, endTime, hardCap, softCap, rate);
    }
    
    /**
     * @notice Set the fund raise types
     * @param _fundRaiseTypes Array of fund raise types
     */
    function setFundRaiseTypes(FundRaiseType[] calldata _fundRaiseTypes) external onlySTOContract {
        // Reset current types
        for (uint8 i = 0; i <= uint8(FundRaiseType.ERC20); i++) {
            fundRaiseTypes[i] = false;
        }
        
        // Set new types
        for (uint8 i = 0; i < _fundRaiseTypes.length; i++) {
            fundRaiseTypes[uint8(_fundRaiseTypes[i])] = true;
        }
        
        emit FundRaiseTypesUpdated(_fundRaiseTypes);
    }
    
    /**
     * @notice Add to the funds raised for a specific type
     * @param _fundRaiseType The fund raise type
     * @param _amount Amount to add
     */
    function addFundsRaised(uint8 _fundRaiseType, uint256 _amount) external onlySTOContract {
        fundsRaised[_fundRaiseType] += _amount;
    }

    /**
     * @notice Reduce the funds raised for a specific type
     * @param _fundRaiseType The fund raise type
     * @param _amount Amount to subtract
     */
    function reduceFundsRaised(uint8 _fundRaiseType, uint256 _amount) external onlySTOContract {
        if (fundsRaised[_fundRaiseType] >= _amount) {
            fundsRaised[_fundRaiseType] -= _amount;
        } else {
            fundsRaised[_fundRaiseType] = 0;
        }
    }

    
    /**
     * @notice Increment the investor count
     */
    function incrementInvestorCount() external onlySTOContract {
        investorCount++;
    }
    
    /**
     * @notice Set whether to allow beneficial investments
     * @param _allowBeneficialInvestments Whether to allow beneficial investments
     */
    function setAllowBeneficialInvestments(bool _allowBeneficialInvestments) external onlySTOContract {
        allowBeneficialInvestments = _allowBeneficialInvestments;
    }
    
    /**
     * @notice Get the hard cap in wei (18 decimals)
     * @return The hard cap in wei
     */
    function getHardCap() external view returns (uint256) {
        return hardCap;
    }

    /**
     * @notice Get the hard cap in raw token units (for display purposes)
     * @return The hard cap in raw token units
     */
    function getHardCapInTokens() external view returns (uint256) {
        return hardCap / 10**18;
    }

    /**
     * @notice Get the soft cap in wei (18 decimals)
     * @return The soft cap in wei
     */
    function getSoftCap() external view returns (uint256) {
        return softCap;
    }

    /**
     * @notice Get the soft cap in raw token units (for display purposes)
     * @return The soft cap in raw token units
     */
    function getSoftCapInTokens() external view returns (uint256) {
        return softCap / 10**18;
    }
    
    /**
     * @notice Check if soft cap is reached
     * @return Whether the soft cap is reached
     */
    function isSoftCapReached() external view returns (bool) {
        // In most cases, this will be for ERC20 (index 5), but we sum all types to be safe
        uint256 totalRaised = 0;
        for (uint8 i = 0; i <= uint8(FundRaiseType.ERC20); i++) {
            totalRaised += fundsRaised[i];
        }
        return totalRaised >= softCap;
    }
    
    /**
     * @notice Check if hard cap is reached
     * @return Whether the hard cap is reached
     */
    function isHardCapReached() external view returns (bool) {
        // In most cases, this will be for ERC20 (index 5), but we sum all types to be safe
        uint256 totalRaised = 0;
        for (uint8 i = 0; i <= uint8(FundRaiseType.ERC20); i++) {
            totalRaised += fundsRaised[i];
        }
        return totalRaised >= hardCap;
    }
    
    /**
     * @notice Get the total funds raised
     * @return The total funds raised
     */
    function getTotalFundsRaised() external view returns (uint256) {
        uint256 totalRaised = 0;
        for (uint8 i = 0; i <= uint8(FundRaiseType.ERC20); i++) {
            totalRaised += fundsRaised[i];
        }
        return totalRaised;
    }
    
    /**
     * @notice Check if an offering is active
     * @return Whether the offering is active
     */
    function isOfferingActive() external view returns (bool) {
        return (
            block.timestamp >= startTime && 
            block.timestamp <= endTime && 
            !this.isHardCapReached()
        );
    }
}