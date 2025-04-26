// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@ar-security-token/lib/st-identity-registry/src/interfaces/IAttributeRegistry.sol";
import "@ar-security-token/src/interfaces/IToken.sol";
import "@ar-security-token/lib/st-identity-registry/src/libraries/Attributes.sol";
import "../libraries/Events.sol";
import "../libraries/Errors.sol";
import "../libraries/Order.sol";
import "../interfaces/ISignatures.sol";
import "../interfaces/IVerificationManager.sol";
import "./Escrow.sol";
import "../mixins/PricingLogic.sol";
import "./STOConfig.sol";

// Interface ITokenRegistry replaced with IToken imported from ar-security-token

/**
 * @title InvestmentManager
 * @notice Manages token purchase and investment logic for Security Token Offerings
 */
contract InvestmentManager is ReentrancyGuard {
    // Reference to the main STO contract
    address public stoContract;
    
    // The token being used for the investment
    IERC20 public investmentToken;
    
    // The security token being sold
    address public securityToken;
    
    // The escrow contract
    Escrow public escrow;
    
    // The pricing logic contract
    PricingLogic public pricingLogic;
    
    // Configuration contract
    STOConfig public stoConfig;
    
    // Verification manager for compliance checks
    IVerificationManager public verificationManager;
    
    // Flag indicating if this is a Rule506c compliant offering
    bool public isRule506cOffering;
    
    // Flag for allowing beneficial investments
    bool public allowBeneficialInvestments;

    // Signatures contract for verifying orders
    address public signaturesContract;
    
    // Mapping of investor to nonce (for replay protection)
    mapping(address => uint256) public nonces;
    
    // State tracking
    mapping(address => bool) public isInvestor;
    address[] private _investors;
    
    // Events
    event InvestmentProcessed(
        address indexed buyer, 
        address indexed beneficiary, 
        uint256 investedAmount, 
        uint256 tokenAmount, 
        uint256 refundAmount
    );
    
    /**
     * @notice Constructor
     * @param _stoContract Address of the main STO contract
     * @param _securityToken Address of the security token
     * @param _investmentToken Address of the token used for investment
     * @param _escrow Address of the escrow contract
     * @param _pricingLogic Address of the pricing logic contract
     * @param _isRule506c Flag indicating if this is a Rule506c compliant offering
     * @param _verificationManager Address of the verification manager (can be address(0) if not yet created)
     */
    constructor(
        address _stoContract,
        address _securityToken,
        address _investmentToken,
        address _escrow,
        address _pricingLogic,
        bool _isRule506c,
        address _verificationManager
    ) {
        require(_stoContract != address(0), "STO contract cannot be zero");
        require(_securityToken != address(0), "Security token cannot be zero");
        require(_investmentToken != address(0), "Investment token cannot be zero");
        require(_escrow != address(0), "Escrow cannot be zero");
        require(_pricingLogic != address(0), "Pricing logic cannot be zero");
        
        stoContract = _stoContract;
        securityToken = _securityToken;
        investmentToken = IERC20(_investmentToken);
        escrow = Escrow(_escrow);
        pricingLogic = PricingLogic(_pricingLogic);
        isRule506cOffering = _isRule506c;
        allowBeneficialInvestments = true; // Default to allowing different beneficiaries
        
        // Create the configuration contract
        stoConfig = new STOConfig(_stoContract, _securityToken, _isRule506c);
        
        // Set the verification manager if provided
        if (_verificationManager != address(0)) {
            verificationManager = IVerificationManager(_verificationManager);
        }
    }
    
    /**
     * @notice Set the time parameters for the offering
     * @param _startTime The start time of the offering
     * @param _endTime The end time of the offering
     */
    function setTimeParameters(uint256 _startTime, uint256 _endTime) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(_startTime < _endTime, "Start time must be before end time");
        
        // Update the configuration
        // Note: This assumes other parameters will be set separately
        address payable fundsReceiver = payable(address(0)); // Will be set in full configure call
        stoConfig.configure(
            _startTime,
            _endTime,
            0, // Hardcap will be set separately
            0, // Softcap will be set separately
            0, // Rate will be set separately
            fundsReceiver,
            address(investmentToken)
        );
    }
    
    /**
     * @notice Change whether beneficial investments are allowed
     * @param _allowBeneficialInvestments Flag to allow/disallow beneficial investments
     */
    function setAllowBeneficialInvestments(bool _allowBeneficialInvestments) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(_allowBeneficialInvestments != allowBeneficialInvestments, "Value hasn't changed");
        allowBeneficialInvestments = _allowBeneficialInvestments;
        
        // Update the configuration
        stoConfig.setAllowBeneficialInvestments(_allowBeneficialInvestments);
        
        emit Events.SetAllowBeneficialInvestments(allowBeneficialInvestments);
    }
    
    /**
     * @notice Purchase tokens with ERC20 token
     * @param _buyer Address performing the token purchase (sender)
     * @param _beneficiary Address to receive the tokens
     * @param _investedAmount Amount of ERC20 tokens to invest
     * @return tokens Amount of tokens purchased
     * @return refund Amount refunded if any
     */
    function buyTokens(
        address _buyer, 
        address _beneficiary, 
        uint256 _investedAmount
    ) 
        external
        nonReentrant 
        returns (uint256 tokens, uint256 refund) 
    {
        require(msg.sender == stoContract, "Only STO contract can call");
        
        // Check if the offering allows beneficial investments
        if (!stoConfig.allowBeneficialInvestments()) {
            require(_beneficiary == _buyer, "Beneficiary address does not match buyer");
        }

        require(_investedAmount > 0, "Investment amount must be greater than 0");
        require(!escrow.isSTOClosed(), "STO is closed");
        
        // Process the transaction
        (tokens, refund) = _processTx(_beneficiary, _investedAmount);
        
        // Track investor for later use
        if (!isInvestor[_beneficiary]) {
            _investors.push(_beneficiary);
            isInvestor[_beneficiary] = true;
            
            // Update investor count in the config
            stoConfig.incrementInvestorCount();
        }
        
        emit InvestmentProcessed(_buyer, _beneficiary, _investedAmount, tokens, refund);
        return (tokens, refund);
    }
    
    /**
     * @notice Execute a signed order from an investor
     * @param _sender Address executing the order (usually an operator)
     * @param order The order details signed by the investor
     * @param signature The EIP-712 signature from the investor
     * @return tokens Amount of tokens purchased
     * @return refund Amount refunded if any
     */
    function executeSignedOrder(
        address _sender,
        Order.OrderInfo calldata order,
        bytes calldata signature
    ) 
        external
        nonReentrant 
        returns (uint256 tokens, uint256 refund)
    {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(signaturesContract != address(0), "Signatures contract not set");
        
        // Verify the investor's signature
        require(ISignatures(signaturesContract).isValidSignature(order, signature, order.investor), 
            "Invalid investor signature");
        
        // Verify the nonce to prevent replay attacks
        require(nonces[order.investor] == order.nonce, "Invalid nonce");
        
        // Increment the nonce
        nonces[order.investor]++;
        
        // Process the order
        require(order.investmentToken == address(investmentToken), "Invalid investment token");
        require(order.investmentTokenAmount > 0, "Investment amount must be greater than 0");
        require(!escrow.isSTOClosed(), "STO is closed");
        
        // Process the transaction
        (tokens, refund) = _processTx(order.investor, order.investmentTokenAmount);
        
        // Track investor for later use
        if (!isInvestor[order.investor]) {
            _investors.push(order.investor);
            isInvestor[order.investor] = true;
            stoConfig.incrementInvestorCount();
        }
        
        emit InvestmentProcessed(_sender, order.investor, order.investmentTokenAmount, tokens, refund);
        emit Events.OrderExecuted(order.investor, order.investmentTokenAmount, tokens, order.nonce);
        
        return (tokens, refund);
    }
    
    /**
     * @notice Get the current nonce for an investor
     * @param investor The investor address
     * @return The current nonce
     */
    function getNonce(address investor) external view returns (uint256) {
        return nonces[investor];
    }
    
    /**
     * @notice Increment the nonce for an investor
     * @param investor Address of the investor
     * @return The new nonce value
     */
    function incrementNonce(address investor) external returns (uint256) {
        require(msg.sender == stoContract, "Only STO contract can call");
        nonces[investor]++;
        return nonces[investor];
    }
    
    /**
     * @notice Set the signatures contract
     * @param _signaturesContract Address of the new signatures contract
     */
    function setSignaturesContract(address _signaturesContract) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(_signaturesContract != address(0), "Signatures contract cannot be zero");
        signaturesContract = _signaturesContract;
    }
    
    /**
     * @notice Set the verification manager
     * @param _verificationManager Address of the new verification manager
     */
    function setVerificationManager(address _verificationManager) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(_verificationManager != address(0), "Verification manager cannot be zero");
        verificationManager = IVerificationManager(_verificationManager);
    }
    
    /**
     * @notice Get all investors
     * @return Array of investor addresses
     */
    function getAllInvestors() external view returns (address[] memory) {
        return _investors;
    }
    
    /**
     * @notice Add a new investor to the list
     * @param investor Address of the investor to add
     * @return Whether the investor was newly added
     */
    function addInvestor(address investor) external returns (bool) {
        require(msg.sender == stoContract, "Only STO contract can call");
        
        if (!isInvestor[investor]) {
            _investors.push(investor);
            isInvestor[investor] = true;
            return true;
        }
        
        return false;
    }
    
    /**
     * @notice Set the fund raise type (for tracking purposes)
     * @param fundRaiseType The fund raise type enum value
     */
    function setFundRaiseType(uint8 fundRaiseType) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        
        // Convert to array of one element
        STOConfig.FundRaiseType[] memory types = new STOConfig.FundRaiseType[](1);
        types[0] = STOConfig.FundRaiseType(fundRaiseType);
        
        // Update the configuration
        stoConfig.setFundRaiseTypes(types);
    }
    
    /**
     * @notice Configure caps and rate
     * @param _hardCap The hard cap value
     * @param _softCap The soft cap value
     * @param _rate The exchange rate
     * @param _fundsReceiver The receiver of funds
     */
    function configureCaps(
        uint256 _hardCap,
        uint256 _softCap,
        uint256 _rate,
        address payable _fundsReceiver
    ) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(_hardCap > 0, "Hard cap must be greater than 0");
        require(_softCap > 0, "Soft cap must be greater than 0");
        require(_rate > 0, "Rate must be greater than 0");
        require(_fundsReceiver != address(0), "Funds receiver cannot be zero");
        
        // Get current time parameters from the configuration
        uint256 startTime = stoConfig.startTime();
        uint256 endTime = stoConfig.endTime();
        
        // Update the configuration with all parameters
        stoConfig.configure(
            startTime,
            endTime,
            _hardCap,
            _softCap,
            _rate,
            _fundsReceiver,
            address(investmentToken)
        );
    }
    
    /**
     * @notice Process a transaction for token purchase
     * @param _beneficiary Address to receive the tokens
     * @param _investedAmount Amount of investment token
     * @return tokens Amount of tokens purchased
     * @return refund Amount to refund if any
     */
    function _processTx(
        address _beneficiary, 
        uint256 _investedAmount
    ) 
        internal 
        returns (uint256 tokens, uint256 refund) 
    {
        _preValidatePurchase(_beneficiary, _investedAmount);
        
        // Calculate token amount to be created
        (tokens, refund) = _getTokenAmount(_investedAmount);
        
        // Check if this transaction would exceed the hard cap
        uint256 currentTokensSold = escrow.getTotalTokensSold();
        uint256 hardCapLimit = stoConfig.getHardCap();
        
        // If this transaction would exceed the hard cap, adjust the tokens and refund
        if (currentTokensSold + tokens > hardCapLimit) {
            uint256 allowedTokens = hardCapLimit - currentTokensSold;
            
            // Calculate adjusted investment and refund amounts
            uint256 originalRate = tokens * 1e18 / (_investedAmount - refund);
            uint256 adjustedInvestment = allowedTokens * 1e18 / originalRate;
            uint256 additionalRefund = (_investedAmount - refund) - adjustedInvestment;
            
            // Update tokens and refund values
            tokens = allowedTokens;
            refund += additionalRefund;
        }
        
        uint256 netInvestment = _investedAmount - refund;

        // Update state in the configuration
        stoConfig.updateFundsRaised(uint8(STOConfig.FundRaiseType.ERC20), int256(netInvestment));
        
        // Deposit funds and token allocation in escrow
        escrow.deposit(_beneficiary, netInvestment, tokens);
        
        return (tokens, refund);
    }
    
    /**
     * @notice Validation of an incoming purchase
     * @param _beneficiary Address to receive tokens
     * @param _investedAmount Amount of investment
     */
    function _preValidatePurchase(address _beneficiary, uint256 _investedAmount) internal view {
        require(_beneficiary != address(0), "Beneficiary address should not be 0x");
        require(_investedAmount != 0, "Amount invested should not be equal to 0");
        
        // Check minimum investment amount if pricing logic specifies one
        uint256 minAmount = pricingLogic.minInvestment();
        if (minAmount > 0) {
            require(_investedAmount >= minAmount, "Investment amount is below minimum");
        }
        
        require(_canBuy(_beneficiary), "Investor lacks required attributes");
        
        // Check if the offering is within its time bounds using the config
        uint256 startTime = stoConfig.startTime();
        uint256 endTime = stoConfig.endTime();
        require(block.timestamp >= startTime && block.timestamp <= endTime, "Offering is closed/Not yet started");
    }
    
    /**
     * @notice Check if an address is allowed to buy tokens
     * @param _investor Address to check
     * @return Whether the address can buy tokens
     */
    function _canBuy(address _investor) internal view returns (bool) {
        if (isRule506cOffering) {
            // If verification manager is set, use it to check verification status
            if (address(verificationManager) != address(0)) {
                return verificationManager.isInvestorVerified(_investor);
            }
            
            // Fallback to direct attribute registry check
            try IToken(securityToken).attributeRegistry() returns (IAttributeRegistry attributeRegistry) {
                // Check if investor has the ACCREDITED_INVESTOR attribute
                try attributeRegistry.hasAttribute(_investor, Attributes.ACCREDITED_INVESTOR) returns (bool hasAttribute) {
                    return hasAttribute;
                } catch {
                    return false;
                }
            } catch {
                return false;
            }
        }
        
        // For non-regulated offerings, allow any address to buy
        return true;
    }

    /**
     * @notice Calculates token amount using the rate and caps
     * @param _investedAmount Amount of investment tokens
     * @return tokens Number of tokens to be issued
     * @return refund Amount to be refunded
     */
    function _getTokenAmount(uint256 _investedAmount) internal view returns(uint256 tokens, uint256 refund) {
        // Get token amount from pricing logic
        return pricingLogic.calculateTokenAmount(_investedAmount);
    }
    
}