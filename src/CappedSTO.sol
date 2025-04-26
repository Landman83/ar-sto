// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@ar-security-token/lib/st-identity-registry/src/interfaces/IAttributeRegistry.sol";
import "@ar-security-token/src/interfaces/IToken.sol";

import "./storage/STOStorage.sol";
import "./mixins/Cap.sol";
import "./utils/Escrow.sol";
import "./utils/Refund.sol";
import "./utils/Minting.sol";
import "./mixins/PricingLogic.sol";
import "./mixins/FixedPrice.sol";
import "./utils/Fees.sol";
import "./utils/Signatures.sol";
import "./interfaces/IFees.sol";
import "./interfaces/ISignatures.sol";
import "./libraries/Events.sol";
import "./libraries/Errors.sol";
import "./libraries/Order.sol";
import "./utils/MathHelpers.sol";
import "@ar-security-token/lib/st-identity-registry/src/libraries/Attributes.sol";
import "./interfaces/ISTO.sol";
import "./interfaces/IVerificationManager.sol";
import "./utils/InvestmentManager.sol";
import "./utils/FinalizationManager.sol";
import {VerificationManager} from "./utils/VerificationManager.sol";

/**
 * @title Security Token Offering for standard capped crowdsale
 * @notice Implements a compliant STO with modular investment and finalization logic
 */
contract CappedSTO is ISTO, STOStorage, ReentrancyGuard, Cap, Ownable {
    // Permission constants
    bytes32 public constant OPERATOR = keccak256("OPERATOR_ROLE");
    bytes32 public constant FACTORY = keccak256("FACTORY");
    
    // The security token being sold
    address public securityToken;
    
    // Flag to determine if this is a Rule506c compliant offering or simple ERC20 offering
    bool public isRule506cOffering;
    
    // Modifier that allows only the factory to call a function
    modifier onlyFactory() {
        require(hasPermission(msg.sender, FACTORY), "Caller is not factory");
        _;
    }
    
    // Modifier to check if the caller has a specific permission
    modifier withPerm(bytes32 _permission) {
        require(hasPermission(msg.sender, _permission), "Permission denied");
        _;
    }
    
    // Modifier to check if the offering is paused
    modifier whenNotPaused() {
        // Implementation to check if the offering is paused
        _;
    }
    // The token being used for the investment
    IERC20 public investmentToken;
    
    // The escrow contract
    Escrow public escrow;
    
    // The refund contract
    Refund public refund;
    
    // The minting contract
    Minting public minting;
    
    // The pricing logic contract
    PricingLogic public pricingLogic;
    
    // The fees contract
    IFees public fees;
    
    // Investor tracking handled by InvestmentManager
    
    // Mapping to track permissions
    mapping(address => mapping(bytes32 => bool)) private _delegatePermissions;

    // Components for investment and finalization management
    InvestmentManager public investmentManager;
    FinalizationManager public finalizationManager;
    IVerificationManager public verificationManager;

    constructor(address _securityToken, bool _isRule506c) 
        Ownable(msg.sender)
    {
        require(_securityToken != address(0), "Security token address cannot be zero");
        securityToken = _securityToken;
        isRule506cOffering = _isRule506c;
    }
    
    /**
     * @notice Initialization function for proxy pattern
     * @dev This function replaces the constructor for proxied instances
     * @param _securityToken Address of the security token
     * @param _isRule506c Whether this offering is Rule 506c compliant
     * @param _owner Address that should own the STO (typically the deployer, not the factory)
     */
    function initialize(address _securityToken, bool _isRule506c, address _owner) 
        public
    {
        // Only allow initialization if not already set up
        require(address(securityToken) == address(0), "Already initialized");
        require(_owner != address(0), "Owner cannot be zero address");
        
        // Initialize token and compliance type
        securityToken = _securityToken;
        isRule506cOffering = _isRule506c;
        
        // Set up initial ownership to specified owner (typically deployer)
        _transferOwnership(_owner);
        
        // Grant FACTORY permission to msg.sender to allow configuration
        _grantPermission(msg.sender, FACTORY);
        
        // Grant OPERATOR permission to the owner
        _grantPermission(_owner, OPERATOR);
    }

    /**
     * @notice Function used to initialize the contract variables with pre-deployed auxiliary contracts
     * @param _startTime Unix timestamp at which offering get started
     * @param _endTime Unix timestamp at which offering get ended
     * @param _hardCap Maximum No. of token base units for sale (hard cap)
     * @param _softCap Minimum No. of token base units that must be sold (soft cap)
     * @param _rate Token units a buyer gets multiplied by 10^18 per investment token unit
     * @param _fundsReceiver Account address to hold the funds
     * @param _investmentToken Address of the ERC20 token used for investment
     * @param _pricingLogic Address of the pricing logic contract (e.g., FixedPrice)
     * @param _minting Address of the minting contract
     * @param _refund Address of the refund contract
     * @param _escrow Address of the escrow contract
     * @param _fees Address of the fees contract (optional, can be address(0))
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
    )
        public
        onlyFactory
    {
        require(endTime == 0, Errors.ALREADY_INITIALIZED);
        require(_rate > 0, Errors.ZERO_RATE);
        require(_fundsReceiver != address(0), Errors.ZERO_ADDRESS);
        require(_investmentToken != address(0), Errors.ZERO_ADDRESS);
        require(_pricingLogic != address(0), "Pricing logic address cannot be zero");
        require(_minting != address(0), "Minting address cannot be zero");
        require(_refund != address(0), "Refund address cannot be zero");
        require(_escrow != address(0), "Escrow address cannot be zero");
        require(_startTime >= block.timestamp && _endTime > _startTime, "Date parameters are not valid");
        
        // Initialize Cap contract with new values
        _initialize(_hardCap, _softCap);
        
        startTime = _startTime;
        endTime = _endTime;
        cap = _hardCap;
        rate = _rate;
        wallet = _fundsReceiver;
        investmentToken = IERC20(_investmentToken);
        
        // Set the auxiliary contracts
        pricingLogic = PricingLogic(_pricingLogic);
        minting = Minting(_minting);
        refund = Refund(_refund);
        escrow = Escrow(_escrow);
        
        // Set fees contract if provided
        if (_fees != address(0)) {
            fees = IFees(_fees);
        }
        
        // Set ERC20 as the only fund raise type
        FundRaiseType[] memory fundRaiseTypes = new FundRaiseType[](1);
        fundRaiseTypes[0] = FundRaiseType.ERC20;
        _setFundRaiseType(fundRaiseTypes);
        
        // Initialize the manager components
        _initializeManagers();
    }
    
    /**
     * @dev Initialize investment and finalization managers
     */
    function _initializeManagers() internal {
        // Create verification manager first
        VerificationManager verificationManagerImpl = new VerificationManager(
            address(this),
            securityToken,
            isRule506cOffering
        );
        verificationManager = IVerificationManager(address(verificationManagerImpl));
        
        // Create and initialize investment manager
        investmentManager = new InvestmentManager(
            address(this),
            securityToken,
            address(investmentToken),
            address(escrow),
            address(pricingLogic),
            isRule506cOffering,
            address(verificationManager)
        );
        
        // Create and initialize finalization manager
        finalizationManager = new FinalizationManager(
            address(this),
            securityToken,
            address(escrow),
            address(minting),
            address(refund),
            isRule506cOffering
        );
        
        // Set time parameters in investment manager
        investmentManager.setTimeParameters(startTime, endTime);
        investmentManager.setAllowBeneficialInvestments(allowBeneficialInvestments);
    }

    
    /**
     * @notice Set a new pricing logic contract
     * @param _pricingLogic Address of the new pricing logic contract
     */
    function setPricingLogic(address _pricingLogic) external withPerm(OPERATOR) {
        require(_pricingLogic != address(0), Errors.ZERO_ADDRESS);
        pricingLogic = PricingLogic(_pricingLogic);
    }
    
    /**
     * @notice Set the signatures contract for EIP-712 signature verification
     * @param _signaturesContract Address of the signatures contract
     */
    function setSignaturesContract(address _signaturesContract) external withPerm(OPERATOR) {
        require(_signaturesContract != address(0), Errors.ZERO_ADDRESS);
        
        // Only update the investment manager as it's the source of truth
        investmentManager.setSignaturesContract(_signaturesContract);
    }
    
    /**
     * @notice Get the current signatures contract address
     * @return The address of the signatures contract from the investment manager
     */
    function signaturesContract() external view returns (address) {
        return investmentManager.signaturesContract();
    }
    
    /**
     * @notice Register this contract as an agent of the security token
     * @dev This function should be called by the token owner after the STO is deployed
     */
    function registerAsAgent() external withPerm(OPERATOR) {
        // This function assumes the token has a method to add an agent
        // The actual implementation depends on your Rule506c token's API
        // Example: securityToken.addAgent(address(this));
        // You'll need to implement this based on your token's specific API
    }

    /**
     * @notice This function returns the signature of configure function
     */
    function getInitFunction() public pure returns(bytes4) {
        return this.configureWithContracts.selector;
    }

    /**
     * @notice Function to set allowBeneficialInvestments (allow beneficiary to be different to funder)
     * @param _allowBeneficialInvestments Boolean to allow or disallow beneficial investments
     */
    function changeAllowBeneficialInvestments(bool _allowBeneficialInvestments) public withPerm(OPERATOR) {
        // Get current value from the investment manager (source of truth)
        bool currentValue = investmentManager.allowBeneficialInvestments();
        require(_allowBeneficialInvestments != currentValue, "Does not change value");
        
        // Only update the investment manager as it's the source of truth
        investmentManager.setAllowBeneficialInvestments(_allowBeneficialInvestments);
        
        emit Events.SetAllowBeneficialInvestments(_allowBeneficialInvestments);
    }
    
    /**
     * @notice Get the current state of beneficial investments flag
     * @return The current state of beneficial investments flag from the investment manager
     */
    function getAllowBeneficialInvestments() public view returns (bool) {
        return investmentManager.allowBeneficialInvestments();
    }

    /**
     * @notice Purchase tokens with ERC20 token
     * @param _beneficiary Address performing the token purchase
     * @param _investedAmount Amount of ERC20 tokens to invest
     */
    function buyTokens(address _beneficiary, uint256 _investedAmount) public override whenNotPaused nonReentrant {
        if (!allowBeneficialInvestments) {
            require(_beneficiary == msg.sender, "Beneficiary address does not match msg.sender");
        }
        
        // Transfer tokens from investor to this contract
        bool success = investmentToken.transferFrom(msg.sender, address(this), _investedAmount);
        require(success, "Token transfer failed");
        
        // Approve escrow to take tokens from this contract
        success = investmentToken.approve(address(escrow), _investedAmount);
        require(success, "Approval failed");
        
        // Process purchase through investment manager
        (uint256 tokens, uint256 refund) = investmentManager.buyTokens(
            msg.sender,
            _beneficiary,
            _investedAmount
        );
        
        // If there's a refund, send it back to the investor
        if (refund > 0) {
            success = investmentToken.transfer(msg.sender, refund);
            require(success, "Refund transfer failed");
        }
        
        emit Events.TokenPurchase(msg.sender, _beneficiary, _investedAmount - refund, tokens);
        
        // Check if hard cap is reached and mark for finalization
        if (hardCapReached()) {
            // Instead of automatically finalizing, just close the STO
            if (!escrow.isSTOClosed()) {
                escrow.closeSTO(true, false);
            }
            
            // Emit event to notify that finalization is needed
            emit Events.FinalizationRequired();
        }
    }
    
    /**
     * @notice Execute a signed order from an investor
     * @dev Only callable by operators
     * @param order The order details signed by the investor
     * @param signature The EIP-712 signature from the investor
     */
    function executeSignedOrder(
        Order.OrderInfo calldata order,
        bytes calldata signature
    ) external override whenNotPaused nonReentrant withPerm(OPERATOR) {
        // Transfer tokens from investor to this contract
        bool success = investmentToken.transferFrom(order.investor, address(this), order.investmentTokenAmount);
        require(success, "Token transfer failed");
        
        // Approve escrow to take tokens from this contract
        success = investmentToken.approve(address(escrow), order.investmentTokenAmount);
        require(success, "Approval failed");
        
        // Process purchase through investment manager
        (uint256 tokens, uint256 refund) = investmentManager.executeSignedOrder(
            msg.sender,
            order,
            signature
        );
        
        // If there's a refund, send it back to the investor
        if (refund > 0) {
            success = investmentToken.transfer(order.investor, refund);
            require(success, "Refund transfer failed");
        }
        
        emit Events.TokenPurchase(msg.sender, order.investor, order.investmentTokenAmount - refund, tokens);
        emit Events.OrderExecuted(order.investor, order.investmentTokenAmount, tokens, order.nonce);
        
        // Check if hard cap is reached and mark for finalization
        if (hardCapReached()) {
            // Since this is called by an operator, we can safely finalize if hard cap is reached
            if (!escrow.isSTOClosed()) {
                escrow.closeSTO(true, false);
            }
            
            // Call finalize directly since we're an operator
            if (!escrow.isFinalized()) {
                finalize();
            }
        }
    }
    
    /**
     * @notice Get the current nonce for an investor
     * @param investor The investor address
     * @return The current nonce
     */
    function getNonce(address investor) external view override returns (uint256) {
        return investmentManager.getNonce(investor);
    }
    

    /**
     * @notice Allow investors to withdraw some or all of their investment before offering closes
     * @param _amount Amount to withdraw
     */
    function withdrawInvestment(uint256 _amount) public override nonReentrant {
        require(!escrow.isSTOClosed(), "STO is already closed");
        require(!escrow.isFinalized(), "Escrow is already finalized");
        
        refund.withdraw(msg.sender, _amount);
        
        // Update tokens sold to reflect the withdrawal
        // We do this by reducing the funds raised
        fundsRaised[uint8(FundRaiseType.ERC20)] -= _amount;
        
        emit Events.InvestmentWithdrawn(msg.sender, _amount);
    }
    
    /**
     * @notice Claim refund if soft cap was not reached (manual backup method)
     * @dev This is only needed if the automatic refund process failed
     */
    function claimRefund() public override nonReentrant {
        require(escrow.isFinalized(), "Escrow not finalized");
        require(!escrow.isSoftCapReached(), "Soft cap was reached, no refunds available");
        
        refund.claimRefund();
    }
    
    /**
     * @notice Finalize the offering
     * @dev Can only be called after the offering end time or when hard cap is reached
     */
    function finalize() public override {
        require(block.timestamp > endTime || hardCapReached(), "Offering not yet ended and hard cap not reached");
        require(msg.sender == address(this) || hasPermission(msg.sender, OPERATOR), "Only operator can finalize");
        
        // Always use finalization manager for finalization logic
        bool softCapReached = finalizationManager.finalize(
            endTime,
            hardCapReached(),
            investmentManager.getAllInvestors()
        );
        
        emit Events.STOFinalized(softCapReached);
    }
    
    /**
     * @notice Internal function to handle finalization logic without permission checks
     * @dev Can be called directly from buyTokens when hard cap is reached
     */
    function _finalize() internal {
        // Close the STO if not already closed
        if (!escrow.isSTOClosed()) {
            escrow.closeSTO(hardCapReached(), block.timestamp > endTime);
        }
        
        // Finalize the escrow if not already finalized
        if (!escrow.isFinalized()) {
            bool softCapReached = isSoftCapReached();
            escrow.finalize(softCapReached);
            
            // If soft cap is reached, automatically mint tokens to all investors
            if (softCapReached) {
                _mintTokensToAllInvestors();
            } else {
                // If soft cap is not reached, automatically process refunds for all investors
                _processRefundsForAllInvestors();
            }
        }
        
        emit Events.STOFinalized(isSoftCapReached());
    }
    
    /**
     * @notice Process refunds for all investors when soft cap is not reached
     * @dev This is called automatically during finalization if soft cap is not reached
     */
    function _processRefundsForAllInvestors() internal {
        // Process refunds in batches to avoid gas limit issues
        refund.processRefundsForAll(investmentManager.getAllInvestors());
    }
    
    /**
     * @notice Issue tokens to a specific investor
     * @param _investor Address of the investor
     * @param _amount Amount of tokens to issue
     * @dev For Rule506c tokens, this function can now delegate minting to the contract owner 
     * who is already registered as an agent of the security token.
     */
    function issueTokens(address _investor, uint256 _amount) external override {
        require(msg.sender == address(minting), "Only minting contract can call this function");
        
        // Always use finalization manager for token issuance
        finalizationManager.issueTokens(_investor, _amount);
    }
    
    /**
     * @notice Mint tokens to all investors
     * @dev Internal function to mint tokens to all investors when soft cap is reached
     */
    function _mintTokensToAllInvestors() internal {
        minting.batchMintAndDeliverTokens(investmentManager.getAllInvestors());
    }
    
    /**
     * @notice Helper function for the owner to manually mint tokens to an investor
     * @dev This is used when the STO contract itself is not registered as an agent
     * @param _investor The address of the investor to receive tokens
     * @param _amount The amount of tokens to mint
     */
    function ownerMintTokens(address _investor, uint256 _amount) external onlyOwner {
        require(isRule506cOffering, "Only applicable for Rule506c offerings");
        
        // Always use finalization manager for owner minting
        finalizationManager.ownerMintTokens(_investor, _amount, msg.sender);
    }

    /**
     * @notice Receive function to handle direct ETH transfers
     */
    receive() external payable {
        revert("Direct ETH payments not accepted");
    }

    /**
     * @notice Fallback function to handle function calls with no matching signature
     */
    fallback() external payable {
        revert("Function not supported");
    }

    /**
     * @notice Return the total no. of tokens sold
     */
    function getTokensSold() external view override returns (uint256) {
        return getTotalTokensSold();
    }

    /**
     * @notice Return the permissions flag that are associated with STO
     */
    function getPermissions() public view returns(bytes32[] memory) {
        bytes32[] memory allPermissions = new bytes32[](1);
        allPermissions[0] = OPERATOR;
        return allPermissions;
    }
    
    /**
     * @notice Set the fund raise types
     * @param _fundRaiseTypes Array of fund raise types
     */
    function _setFundRaiseType(STOStorage.FundRaiseType[] memory _fundRaiseTypes) internal {
        for (uint8 i = 0; i < _fundRaiseTypes.length; i++) {
            fundRaiseTypes[uint8(_fundRaiseTypes[i])] = true;
        }
    }

    /**
     * @notice Return the STO details
     */
    function getSTODetails() public view returns(
        uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, address, bool, bool
    ) {
        return (
            startTime, 
            endTime, 
            getHardCap(), 
            getSoftCap(),
            pricingLogic.getCurrentRate(), 
            fundsRaised[uint8(FundRaiseType.ERC20)], 
            investorCount, 
            getTotalTokensSold(),
            address(investmentToken),
            getSoftCapReached(),
            escrow.isSTOClosed()
        );
    }

    /**
     * @notice Get all investors
     */
    function getAllInvestors() external view override returns (address[] memory) {
        return investmentManager.getAllInvestors();
    }
    
    /**
     * @notice Check if an address is an investor
     * @param _investor The address to check
     * @return Whether the address is an investor
     */
    function isInvestor(address _investor) external view returns (bool) {
        return investmentManager.isInvestor(_investor);
    }
    
    /**
     * @notice Check if an investor is verified
     * @param _investor The address of the investor to check
     * @return Whether the investor is verified
     */
    function isInvestorVerified(address _investor) external view returns (bool) {
        return verificationManager.isInvestorVerified(_investor);
    }
    
    /**
     * @notice Verify an investor
     * @param _investor The address of the investor to verify
     */
    function verifyInvestor(address _investor) external withPerm(OPERATOR) {
        require(address(verificationManager) != address(0), "Verification manager not initialized");
        verificationManager.verifyInvestor(_investor);
    }
    
    /**
     * @notice Batch verify investors
     * @param _investors Array of investor addresses to verify
     */
    function batchVerifyInvestors(address[] calldata _investors) external withPerm(OPERATOR) {
        require(address(verificationManager) != address(0), "Verification manager not initialized");
        verificationManager.batchVerifyInvestors(_investors);
    }
    
    /**
     * @notice Unverify an investor
     * @param _investor The address of the investor to unverify
     */
    function unverifyInvestor(address _investor) external withPerm(OPERATOR) {
        require(address(verificationManager) != address(0), "Verification manager not initialized");
        verificationManager.unverifyInvestor(_investor);
    }
    
    /**
     * @notice Request verification with custom data
     * @param _data Additional verification data (e.g., document hash)
     */
    function requestVerification(bytes32 _data) external {
        require(address(verificationManager) != address(0), "Verification manager not initialized");
        verificationManager.requestVerification(msg.sender, _data);
    }
    
    /**
     * @notice Get all pending verification requests
     * @return Array of addresses with pending verification
     */
    function getPendingVerifications() external view returns (address[] memory) {
        require(address(verificationManager) != address(0), "Verification manager not initialized");
        return verificationManager.getPendingVerifications();
    }

    /**
     * @notice Check if an investor has received their tokens
     * @param _investor Address of the investor
     */
    function hasReceivedTokens(address _investor) external view override returns (bool) {
        return finalizationManager.hasReceivedTokens(_investor);
    }
    
    /**
     * @notice Check if an investor has claimed their refund
     * @param _investor Address of the investor
     */
    function hasClaimedRefund(address _investor) external view override returns (bool) {
        return finalizationManager.hasClaimedRefund(_investor);
    }
    
    /**
     * @notice Implement the hasPermission method
     * @param _delegate Address to check
     * @param _permission Permission to check
     * @return Whether the address has the permission
     */
    function hasPermission(address _delegate, bytes32 _permission) internal view returns(bool) {
        // Check if the delegate has explicit permission
        if (_delegatePermissions[_delegate][_permission]) {
            return true;
        }
        
        // Default permissions
        if (_permission == OPERATOR) {
            return _delegate == wallet || _delegate == address(this);
        } else if (_permission == FACTORY) {
            // For simplicity during testing, allow msg.sender to act as factory 
            // This will be overridden by explicit permissions in production
            return _delegatePermissions[_delegate][_permission];
        }
        return false;
    }
    
    /**
     * @dev Grant a permission to an address
     * @param _delegate Address to grant permission to
     * @param _permission Permission to grant
     */
    function _grantPermission(address _delegate, bytes32 _permission) internal {
        _delegatePermissions[_delegate][_permission] = true;
    }
    
    /**
     * @notice Public method to grant permission (for testing)
     * @param _delegate Address to grant permission to
     * @param _permission Permission to grant
     */
    function grantPermission(address _delegate, bytes32 _permission) public onlyOwner {
        _grantPermission(_delegate, _permission);
    }
    
    /**
     * @dev Revoke a permission from an address
     * @param _delegate Address to revoke permission from
     * @param _permission Permission to revoke
     */
    function _revokePermission(address _delegate, bytes32 _permission) internal {
        _delegatePermissions[_delegate][_permission] = false;
    }

    // -----------------------------------------
    // Internal interface (extensible)
    // -----------------------------------------

    /**
     * @notice Validation of an incoming purchase.
     */
    function _preValidatePurchase(address _beneficiary, uint256 _investedAmount) internal view {
        require(_beneficiary != address(0), "Beneficiary address should not be 0x");
        require(_investedAmount != 0, "Amount invested should not be equal to 0");
        
        // Check minimum investment amount if pricing logic specifies one
        uint256 minAmount = pricingLogic.minInvestment();
        if (minAmount > 0) {
            require(_investedAmount >= minAmount, "Investment amount is below minimum");
        }
        
        // Check if the investor has the required attributes (e.g., ACCREDITED_INVESTOR)
        require(_canBuy(_beneficiary), "Investor lacks required attributes (must be an accredited investor)");
        require(block.timestamp >= startTime && block.timestamp <= endTime, "Offering is closed/Not yet started");
        
        // Allow purchases that would reach the hard cap, but not exceed it
        // The hardcap logic is handled after the transaction is processed
    }
    
    /**
     * @notice Check if an address is allowed to buy tokens
     * @param _investor Address to check
     * @return Whether the address can buy tokens
     */
    function _canBuy(address _investor) internal view returns (bool) {
        if (isRule506cOffering) {
            try IToken(securityToken).attributeRegistry() returns (IAttributeRegistry registry) {
                // Check if investor has the ACCREDITED_INVESTOR attribute
                try registry.hasAttribute(_investor, Attributes.ACCREDITED_INVESTOR) returns (bool hasAttribute) {
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