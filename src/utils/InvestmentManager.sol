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
import "../libraries/Withdrawal.sol";
import "../interfaces/ISignatures.sol";
import "../interfaces/IVerificationManager.sol";
import "../interfaces/ICompliance.sol";
import "../interfaces/ISTO.sol";
import "./Escrow.sol";
import "../mixins/PricingLogic.sol";
import "./STOConfig.sol";


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

    // Compliance contract for investor validation
    ICompliance public compliance;
    
    // Mapping of investor to nonce (for replay protection)
    // Used for both signed orders and signed withdrawals
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

    event WithdrawalProcessed(
        address indexed investor,
        uint256 withdrawalAmount
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
     * @param _compliance Address of the compliance contract
     */
    constructor(
        address _stoContract,
        address _securityToken,
        address _investmentToken,
        address _escrow,
        address _pricingLogic,
        bool _isRule506c,
        address _verificationManager,
        address _compliance
    ) {
        require(_stoContract != address(0), Errors.ZERO_ADDRESS);
        require(_securityToken != address(0), Errors.ZERO_ADDRESS);
        require(_investmentToken != address(0), Errors.ZERO_ADDRESS);
        require(_escrow != address(0), Errors.ZERO_ADDRESS);
        require(_pricingLogic != address(0), Errors.ZERO_ADDRESS);
        require(_compliance != address(0), Errors.ZERO_ADDRESS);

        stoContract = _stoContract;
        securityToken = _securityToken;
        investmentToken = IERC20(_investmentToken);
        escrow = Escrow(_escrow);
        pricingLogic = PricingLogic(_pricingLogic);
        isRule506cOffering = _isRule506c;
        allowBeneficialInvestments = true; // Default to allowing different beneficiaries
        compliance = ICompliance(_compliance);
        
        // Note: stoConfig should be set via setSTOConfig after construction
        // Instead of creating a new STOConfig here, we'll use the one set by the STO
        
        // Set the verification manager if provided
        if (_verificationManager != address(0)) {
            verificationManager = IVerificationManager(_verificationManager);
        }
    }
    
    /**
     * @notice Set the STOConfig contract
     * @param _stoConfig Address of the STOConfig contract
     * @dev This connects the InvestmentManager to the authoritative configuration source
     */
    function setSTOConfig(address _stoConfig) external {
        require(msg.sender == stoContract, "Unauthorized");
        require(_stoConfig != address(0), "Zero address");
        
        // Set the config regardless of whether it was previously set or not
        // This allows the STO contract to set the authoritative config
        stoConfig = STOConfig(_stoConfig);
    }
    
    /**
     * @notice Set the time parameters for the offering
     * @param _startTime The start time of the offering
     * @param _endTime The end time of the offering
     */
    function setTimeParameters(uint256 _startTime, uint256 _endTime) external {
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);
        require(_startTime < _endTime, Errors.INVALID_DATES);
        
        // Use the dedicated time parameters configuration method
        // This avoids issues with validation of other parameters
        stoConfig.configureTimeParameters(
            _startTime,
            _endTime,
            address(investmentToken)
        );
    }
    
    /**
     * @notice Change whether beneficial investments are allowed
     * @param _allowBeneficialInvestments Flag to allow/disallow beneficial investments
     */
    function setAllowBeneficialInvestments(bool _allowBeneficialInvestments) external {
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);
        require(_allowBeneficialInvestments != allowBeneficialInvestments, Errors.INVALID_PARAMETER);
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
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);
        
        // Check if the offering allows beneficial investments
        if (!stoConfig.allowBeneficialInvestments()) {
            require(_beneficiary == _buyer, Errors.SELF_TRANSFER_NOT_ALLOWED);
        }

        require(_investedAmount > 0, Errors.ZERO_INVESTMENT);
        require(!escrow.isSTOClosed(), Errors.CLOSED);
        
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
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);
        
        // Get the signatures contract address from the STO contract
        address sigContractAddress;
        try ISTO(stoContract).signaturesContract() returns (address addr) {
            sigContractAddress = addr;
        } catch {
            sigContractAddress = address(0);
        }
        
        // Require a valid signatures contract
        require(sigContractAddress != address(0), Errors.INVALID_OPERATION);
        
        // Verify the investor's signature
        require(ISignatures(sigContractAddress).isValidSignature(order, signature, order.investor), 
            Errors.INVALID_SIGNATURE);
        
        // Verify the nonce to prevent replay attacks
        require(nonces[order.investor] == order.nonce, Errors.INVALID_NONCE);
        
        // Increment the nonce
        nonces[order.investor]++;
        
        // Process the order
        require(order.investmentToken == address(investmentToken), Errors.INVALID_PARAMETER);
        require(order.investmentTokenAmount > 0, Errors.ZERO_INVESTMENT);
        require(!escrow.isSTOClosed(), Errors.CLOSED);
        
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
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);
        nonces[investor]++;
        return nonces[investor];
    }
    
    // Removed setSignaturesContract method - signatures contract is now managed by the STO
    
    /**
     * @notice Set the verification manager
     * @param _verificationManager Address of the new verification manager
     */
    function setVerificationManager(address _verificationManager) external {
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);
        require(_verificationManager != address(0), Errors.ZERO_ADDRESS);
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
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);
        
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
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);

        // Convert to array of one element
        STOConfig.FundRaiseType[] memory types = new STOConfig.FundRaiseType[](1);
        types[0] = STOConfig.FundRaiseType(fundRaiseType);

        // Update the configuration
        stoConfig.setFundRaiseTypes(types);
    }

    /**
     * @notice Verify a signed withdrawal from an investor
     * @param _sender Address executing the withdrawal (usually an operator)
     * @param withdrawal The withdrawal details signed by the investor
     * @param signature The EIP-712 signature from the investor
     */
    function executeSignedWithdrawal(
        address _sender,
        Withdrawal.WithdrawalInfo calldata withdrawal,
        bytes calldata signature
    )
        external
        nonReentrant
    {
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);

        // Get the signatures contract address from the STO contract
        address sigContractAddress;
        try ISTO(stoContract).signaturesContract() returns (address addr) {
            sigContractAddress = addr;
        } catch {
            sigContractAddress = address(0);
        }

        // Require a valid signatures contract
        require(sigContractAddress != address(0), Errors.INVALID_OPERATION);

        // We'll use the same Signatures contract that we use for orders
        // But we need to hash the Withdrawal struct ourselves since Signatures doesn't support it

        // Hash the withdrawal using EIP-712 format
        bytes32 withdrawalHash = keccak256(abi.encode(
            Withdrawal.WITHDRAWAL_TYPEHASH,
            withdrawal.investor,
            withdrawal.investmentToken,
            withdrawal.withdrawalAmount,
            withdrawal.nonce
        ));

        // Get domain separator from Signatures contract
        bytes32 domainSeparator;
        try ISignatures(sigContractAddress).getDomainSeparator() returns (bytes32 ds) {
            domainSeparator = ds;
        } catch {
            revert(Errors.INVALID_OPERATION);
        }

        // Calculate the complete digest hash for EIP-712
        bytes32 digestHash = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            withdrawalHash
        ));

        // Verify the signature
        address signer = _recoverSigner(digestHash, signature);
        require(signer == withdrawal.investor, Errors.INVALID_SIGNATURE);

        // Verify the nonce to prevent replay attacks
        require(nonces[withdrawal.investor] == withdrawal.nonce, Errors.INVALID_NONCE);

        // Increment the nonce
        nonces[withdrawal.investor]++;

        // Validate the withdrawal request
        require(withdrawal.investmentToken == address(investmentToken), Errors.INVALID_PARAMETER);
        require(withdrawal.withdrawalAmount > 0, Errors.ZERO_INVESTMENT);
        require(!escrow.isSTOClosed(), Errors.CLOSED);
        require(!escrow.isFinalized(), Errors.ESCROW_ALREADY_FINALIZED);

        // Rather than trying to execute the withdrawal directly,
        // we just verify the signature and nonce, then return to the STO
        // The STO will handle calling withdrawInvestment() on behalf of the investor

        // Emit events
        emit WithdrawalProcessed(withdrawal.investor, withdrawal.withdrawalAmount);
    }

    /**
     * @notice Recover signer address from signature and hash
     * @param hash The hash that was signed
     * @param signature The signature bytes
     * @return The recovered signer address
     */
    function _recoverSigner(bytes32 hash, bytes calldata signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        // Extract r, s, v from the signature
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // EIP-2 standardized the signature format
        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");

        return ecrecover(hash, v, r, s);
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
        require(msg.sender == stoContract, Errors.UNAUTHORIZED);
        require(_hardCap > 0, Errors.ZERO_CAP);
        require(_softCap > 0, Errors.ZERO_CAP);
        require(_rate > 0, Errors.ZERO_RATE);
        require(_fundsReceiver != address(0), Errors.ZERO_ADDRESS);
        
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
        // Note: Both escrow.getTotalTokensSold() and stoConfig.getHardCap() are now in wei (18 decimals)
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
        stoConfig.addFundsRaised(uint8(STOConfig.FundRaiseType.ERC20), netInvestment);

        // Instead of directly depositing to escrow, return investment details
        // The STO contract will handle the actual deposit to ensure proper authorization
        return (tokens, refund);
    }
    
    /**
     * @notice Validation of an incoming purchase
     * @param _beneficiary Address to receive tokens
     * @param _investedAmount Amount of investment
     */
    function _preValidatePurchase(address _beneficiary, uint256 _investedAmount) internal view {
        require(_beneficiary != address(0), Errors.ZERO_ADDRESS);
        require(_investedAmount != 0, Errors.ZERO_INVESTMENT);
        
        // Check minimum investment amount if pricing logic specifies one
        uint256 minAmount = pricingLogic.minInvestment();
        if (minAmount > 0) {
            require(_investedAmount >= minAmount, Errors.BELOW_MIN_INVESTMENT);
        }
        
        require(_canBuy(_beneficiary), Errors.COMPLIANCE_CHECK_FAILED);
        
        // Check if the offering is within its time bounds using the config
        uint256 startTime = stoConfig.startTime();
        uint256 endTime = stoConfig.endTime();
        require(block.timestamp >= startTime && block.timestamp <= endTime, Errors.STO_NOT_ACTIVE);
    }
    
    /**
     * @notice Check if an address is allowed to buy tokens
     * @param _investor Address to check
     * @return Whether the address can buy tokens
     */
    function _canBuy(address _investor) internal view returns (bool) {
        // Use the compliance contract to check if investor can buy
        return compliance.canInvestorBuy(
            securityToken,
            _investor,
            address(verificationManager),
            isRule506cOffering
        );
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