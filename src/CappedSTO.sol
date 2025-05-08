// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@ar-security-token/src/interfaces/IToken.sol";

import "./mixins/Cap.sol";
import "./utils/Escrow.sol";
import "./utils/Refund.sol";
import "./utils/Minting.sol";
import "./mixins/PricingLogic.sol";
import "./mixins/Compliance.sol";
import "./utils/Fees.sol";
import "./interfaces/IFees.sol";
import "./interfaces/ICompliance.sol";
import "./libraries/Events.sol";
import "./libraries/CustomErrors.sol";
import "./libraries/Order.sol";
import "./utils/MathHelpers.sol";
import "./interfaces/ISTO.sol";
import "./interfaces/IVerificationManager.sol";
import "./interfaces/IInvestmentManager.sol";
import "./interfaces/IFinalizationManager.sol";
import "./interfaces/ISTOConfig.sol";
import "./utils/InvestmentManager.sol";
import "./utils/FinalizationManager.sol";
import {VerificationManager} from "./utils/VerificationManager.sol";
import "./utils/STOConfig.sol";

/**
 * @title Security Token Offering for standard capped crowdsale
 * @notice Implements a compliant STO with modular investment and finalization logic
 * @dev This contract serves as the main entry point for the STO system but delegates
 *      most functionality to specialized manager components. Each manager component is
 *      the authoritative source of truth for its domain:
 *
 * Component Responsibilities and State Ownership:
 * ---------------------------------------------
 * - InvestmentManager: Owns investor tracking, verification, investment processing
 *   - Authoritative for: allowBeneficialInvestments, investor list, nonces
 *   - Provides: Investor addition and validation, token purchase logic
 *
 * - FinalizationManager: Owns finalization status, token distribution, refund processing
 *   - Authoritative for: finalization status, token receipt status, refund status
 *   - Provides: Token issuance, refund processing, STO finalization
 *
 * - VerificationManager: Owns investor verification status
 *   - Authoritative for: verification status, pending verification requests
 *   - Provides: Investor verification against attribute registry
 *
 * - STOConfig: Owns configuration parameters and fund metrics
 *   - Authoritative for: start/end time, fund raise types, investor counts, caps
 *   - Provides: Configuration parameters, funding stats, cap tracking
 *
 * - Escrow: Owns funds custody, STO status
 *   - Authoritative for: STO closed status, investor deposits, token allocations
 *   - Provides: Fund custody, STO status management
 *
 * - Cap: Owns cap tracking and management
 *   - Authoritative for: hard/soft cap values, tokens sold, cap reached status
 *   - Provides: Cap enforcement, cap reached status
 *
 * Dependencies:
 * -------------
 * - Requires all manager components to be properly initialized
 * - Requires the security token to be a valid token contract
 * - Requires the investment token to be a valid ERC20 token
 * - May require the security token owner to grant agent status to this contract
 */
contract CappedSTO is ISTO, ReentrancyGuard, Cap, Ownable, AccessControl {
    // Role constants
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant FACTORY_ROLE = keccak256("FACTORY_ROLE");
    
    // The security token being sold
    address public securityToken;
    
    // Flag to determine if this is a Rule506c compliant offering or simple ERC20 offering
    bool public isRule506cOffering;
    
    // Modifier that allows only the factory to call a function
    modifier onlyFactory() {
        if (!hasRole(FACTORY_ROLE, msg.sender)) {
            revert Unauthorized(msg.sender, "FACTORY_ROLE");
        }
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

    // Components for investment and finalization management
    // These are exposed publicly so they can be accessed directly by clients
    InvestmentManager public investmentManager;
    FinalizationManager public finalizationManager;
    IVerificationManager public verificationManager;
    ICompliance public compliance;
    
    // Configuration contract for STO parameters
    ISTOConfig public stoConfig;

    /**
     * @notice Constructor requiring all components to be provided
     * @param _securityToken Address of the security token
     * @param _isRule506c Flag indicating Rule 506c compliance
     * @param _investmentToken Address of the investment token
     * @param _escrow Address of the escrow contract
     * @param _refund Address of the refund contract
     * @param _minting Address of the minting contract
     * @param _pricingLogic Address of the pricing logic contract
     * @param _fees Address of the fees contract (optional, can be address(0))
     * @param _investmentManager Address of the investment manager
     * @param _finalizationManager Address of the finalization manager
     * @param _verificationManager Address of the verification manager
     * @param _compliance Address of the compliance contract
     * @param _stoConfig Address of the STO configuration contract
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
    ) Ownable(msg.sender) {
        // Validate all required addresses
        if (_securityToken == address(0)) {
            revert ZeroAddress("securityToken");
        }
        if (_investmentToken == address(0)) {
            revert ZeroAddress("investmentToken");
        }
        if (_escrow == address(0)) {
            revert ZeroAddress("escrow");
        }
        if (_refund == address(0)) {
            revert ZeroAddress("refund");
        }
        if (_minting == address(0)) {
            revert ZeroAddress("minting");
        }
        if (_pricingLogic == address(0)) {
            revert ZeroAddress("pricingLogic");
        }
        if (_investmentManager == address(0)) {
            revert ZeroAddress("investmentManager");
        }
        if (_finalizationManager == address(0)) {
            revert ZeroAddress("finalizationManager");
        }
        if (_verificationManager == address(0)) {
            revert ZeroAddress("verificationManager");
        }
        if (_compliance == address(0)) {
            revert ZeroAddress("compliance");
        }
        if (_stoConfig == address(0)) {
            revert ZeroAddress("stoConfig");
        }
        
        // Set main parameters
        securityToken = _securityToken;
        isRule506cOffering = _isRule506c;
        
        // Set contracts
        investmentToken = IERC20(_investmentToken);
        escrow = Escrow(_escrow);
        refund = Refund(_refund);
        minting = Minting(_minting);
        pricingLogic = PricingLogic(_pricingLogic);
        if (_fees != address(0)) {
            fees = IFees(_fees);
        }
        
        // Set manager components
        investmentManager = InvestmentManager(_investmentManager);
        finalizationManager = FinalizationManager(_finalizationManager);
        verificationManager = IVerificationManager(_verificationManager);
        compliance = ICompliance(_compliance);
        stoConfig = ISTOConfig(_stoConfig);
        
        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(FACTORY_ROLE, msg.sender);
    }
    
    /**
     * @notice Factory helper method to create a new STOConfig instance and initialize it
     * @param _startTime Unix timestamp at which offering get started
     * @param _endTime Unix timestamp at which offering get ended
     * @param _hardCap Maximum No. of token base units for sale (hard cap)
     * @param _softCap Minimum No. of token base units that must be sold (soft cap)
     * @param _rate Token units a buyer gets multiplied by 10^18 per investment token unit
     * @param _fundsReceiver Account address to hold the funds
     * @param _investmentToken Address of the ERC20 token used for investment
     * @return The address of the newly created and initialized STOConfig contract
     */
    function createSTOConfig(
        uint256 _startTime,
        uint256 _endTime,
        uint256 _hardCap,
        uint256 _softCap,
        uint256 _rate,
        address payable _fundsReceiver,
        address _investmentToken
    )
        public
        onlyFactory
        returns (address)
    {
        // Initialize Cap contract with new values for this contract
        _initialize(_hardCap, _softCap);
        
        // Create a new STOConfig contract
        STOConfig newConfig = new STOConfig(
            address(this),
            securityToken,
            isRule506cOffering
        );
        
        // Configure the STOConfig with all parameters
        newConfig.configure(
            _startTime,
            _endTime,
            _hardCap,
            _softCap,
            _rate,
            _fundsReceiver,
            _investmentToken
        );
        
        // Set ERC20 as the only fund raise type
        STOConfig.FundRaiseType[] memory fundRaiseTypes = new STOConfig.FundRaiseType[](1);
        fundRaiseTypes[0] = STOConfig.FundRaiseType.ERC20;
        newConfig.setFundRaiseTypes(fundRaiseTypes);
        
        return address(newConfig);
    }
    
    /**
     * @notice This function returns the signature of the factory method
     */
    function getFactoryFunction() public pure returns(bytes4) {
        return this.createSTOConfig.selector;
    }

    
    /**
     * @notice Set a new pricing logic contract
     * @param _pricingLogic Address of the new pricing logic contract
     */
    function setPricingLogic(address _pricingLogic) external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        
        if (_pricingLogic == address(0)) {
            revert ZeroAddress("pricingLogic");
        }
        
        pricingLogic = PricingLogic(_pricingLogic);
    }
    
    /**
     * @notice Set the signatures contract for EIP-712 signature verification
     * @param _signaturesContract Address of the signatures contract
     */
    function setSignaturesContract(address _signaturesContract) external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        
        if (_signaturesContract == address(0)) {
            revert ZeroAddress("signaturesContract");
        }
        
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
    function registerAsAgent() external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        
        // This function assumes the token has a method to add an agent
        // The actual implementation depends on your Rule506c token's API
        // Example: securityToken.addAgent(address(this));
        // You'll need to implement this based on your token's specific API
    }

    /**
     * @notice This function returns the signature of initialize function
     */
    function getInitFunction() public pure returns(bytes4) {
        return this.createSTOConfig.selector;
    }

    /**
     * @notice Function to set allowBeneficialInvestments (allow beneficiary to be different to funder)
     * @param _allowBeneficialInvestments Boolean to allow or disallow beneficial investments
     * @dev Changes the setting in the investment manager, which is the single source of truth
     *      The allowBeneficialInvestments state in STOStorage is no longer used
     */
    function changeAllowBeneficialInvestments(bool _allowBeneficialInvestments) public {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        
        // Get current value from the investment manager (source of truth)
        bool currentValue = investmentManager.allowBeneficialInvestments();
        if (_allowBeneficialInvestments == currentValue) {
            revert InvalidParameter("allowBeneficialInvestments", "Value is unchanged");
        }
        
        // Only update the investment manager as it's the source of truth
        investmentManager.setAllowBeneficialInvestments(_allowBeneficialInvestments);
        
        emit Events.SetAllowBeneficialInvestments(_allowBeneficialInvestments);
    }
    
    /**
     * @notice Get the current state of beneficial investments flag
     * @return The current state of beneficial investments flag from the investment manager
     * @dev This always returns the value from the investment manager, which is the 
     *      single source of truth for this configuration parameter
     */
    function getAllowBeneficialInvestments() public view returns (bool) {
        return investmentManager.allowBeneficialInvestments();
    }
    
    // -------------------------------------------------------
    // Verification Manager Delegation Methods
    // -------------------------------------------------------
    
    /**
     * @notice Check if an investor is verified
     * @param _investor The address of the investor to check
     * @return Whether the investor is verified
     */
    function isInvestorVerified(address _investor) public view returns (bool) {
        return verificationManager.isInvestorVerified(_investor);
    }
    
    /**
     * @notice Add an investor to the verified list (manual verification)
     * @param _investor The address of the investor to verify
     */
    function verifyInvestor(address _investor) external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        verificationManager.verifyInvestor(_investor);
    }
    
    /**
     * @notice Add multiple investors to the verified list
     * @param _investors Array of investor addresses to verify
     */
    function batchVerifyInvestors(address[] calldata _investors) external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        verificationManager.batchVerifyInvestors(_investors);
    }
    
    /**
     * @notice Remove an investor from the verified list
     * @param _investor The address of the investor to unverify
     */
    function unverifyInvestor(address _investor) external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        verificationManager.unverifyInvestor(_investor);
    }
    
    /**
     * @notice Request verification with custom data
     * @param _investor The address of the investor requesting verification
     * @param _data Additional verification data (e.g., document hash)
     */
    function requestVerification(address _investor, bytes32 _data) external {
        verificationManager.requestVerification(_investor, _data);
    }
    
    /**
     * @notice Get all pending verification requests
     * @return Array of addresses with pending verification
     */
    function getPendingVerifications() external view returns (address[] memory) {
        return verificationManager.getPendingVerifications();
    }
    
    /**
     * @notice Check if an investor has a pending verification
     * @param _investor The address of the investor to check
     * @return Whether the investor has a pending verification
     */
    function hasPendingVerification(address _investor) external view returns (bool) {
        return verificationManager.hasPendingVerification(_investor);
    }
    
    /**
     * @notice Set the attribute registry address
     * @param _attributeRegistry The address of the attribute registry
     */
    function setAttributeRegistry(address _attributeRegistry) external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        verificationManager.setAttributeRegistry(_attributeRegistry);
    }
    
    /**
     * @notice Update the pending verification list to remove verified investors
     */
    function cleanupPendingList() external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        verificationManager.cleanupPendingList();
    }

    /**
     * @notice Purchase tokens with ERC20 token
     * @param _beneficiary Address performing the token purchase
     * @param _investedAmount Amount of ERC20 tokens to invest
     * @dev This is the main entry point for investors to participate in the offering
     *      Steps:
     *      1. Validate beneficial investment rules using InvestmentManager as source of truth
     *      2. Transfer tokens from investor to this contract
     *      3. Approve escrow to take tokens from this contract
     *      4. Delegate to InvestmentManager for all investment processing logic
     *      5. Handle any refunds if needed
     *      6. Check for hard cap and manage finalization
     *
     * Investment validation is delegated to the InvestmentManager which is the 
     * authoritative source for all investment validation logic, including:
     * - Time window validation
     * - Minimum investment checks
     * - Investor verification
     * - Compliance checks
     */
    function buyTokens(address _beneficiary, uint256 _investedAmount) public override whenNotPaused nonReentrant {
        // Get the setting from the investment manager which is single source of truth
        if (!investmentManager.allowBeneficialInvestments() && _beneficiary != msg.sender) {
            revert SelfTransferNotAllowed(msg.sender, _beneficiary);
        }
        
        // Transfer tokens from investor to this contract
        bool success = investmentToken.transferFrom(msg.sender, address(this), _investedAmount);
        if (!success) {
            revert TransferFailed(address(investmentToken), msg.sender, address(this), _investedAmount);
        }
        
        // Approve escrow to take tokens from this contract
        success = investmentToken.approve(address(escrow), _investedAmount);
        if (!success) {
            revert ApprovalFailed(address(investmentToken), address(escrow), _investedAmount);
        }
        
        // Process purchase through investment manager
        // The investment manager is responsible for:
        // - Validating the investment parameters
        // - Calculating token amounts
        // - Depositing funds into escrow
        // - Tracking the investor
        // - Returning any refund amount
        (uint256 tokens, uint256 refund) = investmentManager.buyTokens(
            msg.sender,
            _beneficiary,
            _investedAmount
        );
        
        // If there's a refund, send it back to the investor
        if (refund > 0) {
            success = investmentToken.transfer(msg.sender, refund);
            if (!success) {
                revert RefundFailed(address(investmentToken), msg.sender, refund);
            }
        }
        
        emit Events.TokenPurchase(msg.sender, _beneficiary, _investedAmount - refund, tokens);
        
        // Check if hard cap is reached using STOConfig as the source of truth
        if (stoConfig.isHardCapReached()) {
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
    ) external override whenNotPaused nonReentrant {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        
        // Transfer tokens from investor to this contract
        bool success = investmentToken.transferFrom(order.investor, address(this), order.investmentTokenAmount);
        if (!success) {
            revert TransferFailed(address(investmentToken), order.investor, address(this), order.investmentTokenAmount);
        }
        
        // Approve escrow to take tokens from this contract
        success = investmentToken.approve(address(escrow), order.investmentTokenAmount);
        if (!success) {
            revert ApprovalFailed(address(investmentToken), address(escrow), order.investmentTokenAmount);
        }
        
        // Process purchase through investment manager
        (uint256 tokens, uint256 refund) = investmentManager.executeSignedOrder(
            msg.sender,
            order,
            signature
        );
        
        // If there's a refund, send it back to the investor
        if (refund > 0) {
            success = investmentToken.transfer(order.investor, refund);
            if (!success) {
                revert RefundFailed(address(investmentToken), order.investor, refund);
            }
        }
        
        emit Events.TokenPurchase(msg.sender, order.investor, order.investmentTokenAmount - refund, tokens);
        emit Events.OrderExecuted(order.investor, order.investmentTokenAmount, tokens, order.nonce);
        
        // Check if hard cap is reached using STOConfig as the source of truth
        if (stoConfig.isHardCapReached()) {
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
     * @notice Allow investors to withdraw some or all of their investment before offering closes
     * @param _amount Amount to withdraw
     * @dev This function processes the withdrawal through the refund contract and
     *      updates the funds raised in STOConfig to maintain accurate tracking
     */
    function withdrawInvestment(uint256 _amount) public override nonReentrant {
        // Validate STO status
        if (escrow.isSTOClosed()) {
            revert STOClosed();
        }
        
        if (escrow.isFinalized()) {
            revert EscrowAlreadyFinalized();
        }
        
        // Process the withdrawal through the refund contract
        refund.withdraw(msg.sender, _amount);
        
        // Update funds raised in the STOConfig (single source of truth)
        stoConfig.updateFundsRaised(
            uint8(ISTOConfig.FundRaiseType.ERC20), 
            -int256(_amount)
        );
        
        emit Events.InvestmentWithdrawn(msg.sender, _amount);
    }
    
    /**
     * @notice Claim refund if soft cap was not reached (manual backup method)
     * @dev This is only needed if the automatic refund process failed
     */
    function claimRefund() public override nonReentrant {
        if (!escrow.isFinalized()) {
            revert EscrowNotFinalized();
        }
        
        // Use STOConfig to determine if soft cap was reached
        if (stoConfig.isSoftCapReached()) {
            revert SoftCapAlreadyReached(stoConfig.getSoftCap());
        }
        
        refund.claimRefund();
    }
    
    /**
     * @notice Finalize the offering
     * @dev Can only be called after the offering end time or when hard cap is reached
     *      This method delegates all finalization logic to the FinalizationManager component
     *      which is the authoritative source for finalization status and processing.
     *
     * The FinalizationManager is responsible for:
     * - Determining if the soft cap was reached using STOConfig
     * - Finalizing the escrow
     * - Distributing tokens or processing refunds based on soft cap
     * - Transferring funds to the wallet if successful
     */
    function finalize() public override {
        // Check timing and cap conditions for finalization using STOConfig
        if (!(block.timestamp > stoConfig.endTime() || stoConfig.isHardCapReached())) {
            revert STOAlreadyActive();
        }
        
        // Check permissions
        if (msg.sender != address(this) && !hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }
        
        // Delegate all finalization logic to the FinalizationManager
        bool softCapReached = finalizationManager.finalize(
            stoConfig.endTime(),
            stoConfig.isHardCapReached(),
            investmentManager.getAllInvestors()
        );
        
        emit Events.STOFinalized(softCapReached);
    }
    
    /**
     * @notice Issue tokens to a specific investor
     * @param _investor Address of the investor
     * @param _amount Amount of tokens to issue
     * @dev For Rule506c tokens, this function delegates minting to the contract owner
     *      who is already registered as an agent of the security token.
     *
     * Dependencies:
     * - Can only be called by the Minting contract
     * - Delegates functionality to FinalizationManager which is the authoritative source
     *   for token issuance status and processing
     */
    function issueTokens(address _investor, uint256 _amount) external override {
        // Verify caller permission
        if (msg.sender != address(minting)) {
            revert Unauthorized(msg.sender, "MINTING");
        }
        
        // Always use finalization manager for token issuance
        // The FinalizationManager is responsible for:
        // - Calling the security token to mint tokens
        // - Tracking which investors have received tokens
        // - Ensuring tokens are only issued once per investor
        finalizationManager.issueTokens(_investor, _amount);
    }
    
    /**
     * @notice Helper function for the owner to manually mint tokens to an investor
     * @dev This is used when the STO contract itself is not registered as an agent
     * @param _investor The address of the investor to receive tokens
     * @param _amount The amount of tokens to mint
     */
    function ownerMintTokens(address _investor, uint256 _amount) external onlyOwner {
        if (!isRule506cOffering) {
            revert InvalidOperation("ownerMintTokens", "Not a Rule506c offering");
        }
        
        // Always use finalization manager for owner minting
        finalizationManager.ownerMintTokens(_investor, _amount, msg.sender);
    }

    // Simplified fallback functions
    receive() external payable { revert(); }
    fallback() external payable { revert(); }

    /**
     * @notice Return the permissions flag that are associated with STO
     */
    function getPermissions() public pure returns(bytes32[] memory) {
        bytes32[] memory allPermissions = new bytes32[](1);
        allPermissions[0] = OPERATOR_ROLE;
        return allPermissions;
    }
    
    /**
     * @notice Set the fund raise types in the STOConfig
     * @param _fundRaiseTypes Array of fund raise types
     */
    function setFundRaiseTypes(ISTOConfig.FundRaiseType[] memory _fundRaiseTypes) public onlyFactory {
        // Update the authoritative source
        stoConfig.setFundRaiseTypes(_fundRaiseTypes);
    }

    /**
     * @notice Return the STO details
     * @dev This method aggregates information from multiple authoritative sources
     * to provide a comprehensive view of the STO's current state.
     * 
     * Each value is retrieved from its authoritative source:
     * - Time parameters from STOConfig
     * - Hard/soft cap from STOConfig
     * - Current rate from the PricingLogic contract
     * - Funds raised from STOConfig
     * - Investor count from STOConfig
     * - Tokens sold calculated from rate and funds raised
     * - Investment token from STOConfig
     * - Soft cap reached status from STOConfig
     * - STO closed status from the Escrow contract
     * 
     * @return A tuple containing the following STO details:
     * - startTime: The start time of the offering
     * - endTime: The end time of the offering
     * - hardCap: The hard cap (maximum tokens for sale)
     * - softCap: The soft cap (minimum tokens required for success)
     * - currentRate: The current exchange rate
     * - fundsRaised: Total amount of funds raised
     * - investorCount: Total number of unique investors
     * - tokensSold: Total number of tokens sold
     * - investmentToken: Address of the investment token
     * - softCapReached: Whether the soft cap has been reached
     * - stoClosed: Whether the STO is closed
     */
    function getSTODetails() public view returns(
        uint256, uint256, uint256, uint256, uint256, uint256, uint256, uint256, address, bool, bool
    ) {
        // Calculate tokens sold based on funds raised and rate
        uint256 fundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
        uint256 rate = stoConfig.rate();
        uint256 tokensSold = (fundsRaised * rate) / 1e18;
        
        return (
            stoConfig.startTime(),
            stoConfig.endTime(),
            stoConfig.getHardCap(),
            stoConfig.getSoftCap(),
            pricingLogic.getCurrentRate(),
            fundsRaised,
            stoConfig.investorCount(),
            tokensSold,
            stoConfig.investmentToken(),
            stoConfig.isSoftCapReached(),
            escrow.isSTOClosed()
        );
    }

    // -----------------------------------------
    // Required interface methods from ISTO
    // -----------------------------------------
    
    /**
     * @notice Get the current nonce for an investor (for signed orders)
     * @param investor The investor address
     * @return The current nonce
     */
    function getNonce(address investor) external view override returns (uint256) {
        return investmentManager.getNonce(investor);
    }
    
    /**
     * @notice Get access to the investment manager
     * @return The investment manager contract
     */
    function getInvestmentManager() external view override returns (address) {
        return address(investmentManager);
    }
    
    /**
     * @notice Get access to the finalization manager
     * @return The finalization manager contract 
     */
    function getFinalizationManager() external view override returns (address) {
        return address(finalizationManager);
    }
    
    /**
     * @notice Get access to the verification manager
     * @return The verification manager contract
     */
    function getVerificationManager() external view override returns (address) {
        return address(verificationManager);
    }
    
    /**
     * @notice Return the total number of tokens sold
     * @return The total number of tokens sold
     */
    function getTotalTokensSold() public view override(Cap, ISTO) returns (uint256) {
        // Calculate tokens sold based on funds raised and rate from STOConfig
        uint256 fundsRaised = stoConfig.fundsRaised(uint8(ISTOConfig.FundRaiseType.ERC20));
        uint256 rate = stoConfig.rate();
        return (fundsRaised * rate) / 1e18;
    }
    
    /**
     * @notice Get access to the STO configuration contract
     * @return The STOConfig contract address
     */
    function getSTOConfig() external view returns (address) {
        return address(stoConfig);
    }
}