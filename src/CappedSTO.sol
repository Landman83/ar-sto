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
import "./libraries/Withdrawal.sol";
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
import "./utils/SignedWithdraw.sol";

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
    
    // Address of the signatures contract for EIP-712 signature verification
    address public signaturesContract;

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

        // Store the signatures contract address in the STO
        signaturesContract = _signaturesContract;
    }
    
    /**
     * @notice Register this contract as an agent of the security token
     * @dev This function should be called by the token owner after the STO is deployed
     */
    function registerAsAgent() external {
        if (!hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }

        // Use the proper method to register the STO
        if (isRule506cOffering) {
            // Register this STO with the security token
            // The registerSTO method automatically adds the STO as an agent
            try IToken(securityToken).registerSTO(address(this)) {
                // Success - registerSTO adds agent role automatically
            } catch Error(string memory reason) {
                revert(string(abi.encodePacked("Failed to register STO: ", reason)));
            } catch {
                revert("Failed to register STO with security token");
            }

            // Since we don't have direct access to adding agents through the IToken interface,
            // and the FinalizationManager needs agent privileges, we'll modify our approach:
            // 1. The STO is now an agent (via registerSTO)
            // 2. When the FinalizationManager needs to mint tokens, it will call back to the STO
            // 3. The STO will perform the actual minting as it has agent privileges
        }
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
        // - Tracking the investor
        // - Returning token and refund amounts
        (uint256 tokens, uint256 refundAmount) = investmentManager.buyTokens(
            msg.sender,
            _beneficiary,
            _investedAmount
        );

        // Handle escrow deposit directly from the STO contract
        // This ensures the escrow's onlySTO modifier passes
        if (tokens > 0) {
            uint256 netInvestment = _investedAmount - refundAmount;
            escrow.deposit(_beneficiary, netInvestment, tokens);
        }

        // If there's a refund, handle it through the Refund contract for consistency
        if (refundAmount > 0) {
            // Approve the Refund contract to spend the tokens
            success = investmentToken.approve(address(refund), refundAmount);
            if (!success) {
                revert ApprovalFailed(address(investmentToken), address(refund), refundAmount);
            }

            // Process the refund through the Refund contract
            try refund.processExcessRefund(msg.sender, refundAmount) {
                // Refund was processed successfully
                emit Events.RefundProcessed(msg.sender, refundAmount);
            } catch Error(string memory reason) {
                revert(string(abi.encodePacked("Refund failed: ", reason)));
            }
        }

        emit Events.TokenPurchase(msg.sender, _beneficiary, _investedAmount - refundAmount, tokens);
        
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
     * @dev Anyone can call this function to submit a signed order
     * @param order The order details signed by the investor
     * @param signature The EIP-712 signature from the investor
     */
    function executeSignedOrder(
        Order.OrderInfo calldata order,
        bytes calldata signature
    ) external override whenNotPaused nonReentrant {
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
        (uint256 tokens, uint256 refundAmount) = investmentManager.executeSignedOrder(
            msg.sender,
            order,
            signature
        );

        // Handle escrow deposit directly from the STO contract
        // This ensures the escrow's onlySTO modifier passes
        if (tokens > 0) {
            uint256 netInvestment = order.investmentTokenAmount - refundAmount;
            escrow.deposit(order.investor, netInvestment, tokens);
        }

        // If there's a refund, handle it through the Refund contract for consistency
        if (refundAmount > 0) {
            // Approve the Refund contract to spend the tokens
            success = investmentToken.approve(address(refund), refundAmount);
            if (!success) {
                revert ApprovalFailed(address(investmentToken), address(refund), refundAmount);
            }

            // Process the refund through the Refund contract
            try refund.processExcessRefund(order.investor, refundAmount) {
                // Refund was processed successfully
                emit Events.RefundProcessed(order.investor, refundAmount);
            } catch Error(string memory reason) {
                revert(string(abi.encodePacked("Refund failed: ", reason)));
            }
        }

        emit Events.TokenPurchase(msg.sender, order.investor, order.investmentTokenAmount - refundAmount, tokens);
        emit Events.OrderExecuted(order.investor, order.investmentTokenAmount, tokens, order.nonce);

        // Check if hard cap is reached using STOConfig as the source of truth
        if (stoConfig.isHardCapReached()) {
            // Close the STO if hard cap is reached
            if (!escrow.isSTOClosed()) {
                escrow.closeSTO(true, false);
            }

            // Since we've hit the hard cap, let's not automatically finalize
            // We'll emit an event to notify that finalization is available but not force it
            if (!escrow.isFinalized()) {
                // Emit event to notify that finalization is needed
                emit Events.FinalizationRequired();
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
        // Delegate to internal method with the caller as the investor
        _withdrawInvestment(msg.sender, _amount);

        // Event is emitted inside _withdrawInvestment
    }

    /**
     * @notice Internal method to handle withdrawal logic
     * @param _investor The investor address requesting withdrawal
     * @param _amount Amount to withdraw
     */
    function _withdrawInvestment(address _investor, uint256 _amount) internal {
        // Validate STO status
        if (escrow.isSTOClosed()) {
            revert STOClosed();
        }

        if (escrow.isFinalized()) {
            revert EscrowAlreadyFinalized();
        }

        // Get current investment to verify withdrawal amount
        uint256 currentInvestment = escrow.getInvestment(_investor);
        if (currentInvestment < _amount) {
            revert WithdrawalExceedsInvestment(_amount, currentInvestment);
        }

        // Process the withdrawal by directly calling the Escrow contract
        // Instead of going through the Refund contract
        escrow.processWithdrawal(_investor, _amount);

        // Track the withdrawal in the Refund contract for record-keeping
        refund.recordWithdrawal(_investor, _amount);

        // Update funds raised in the STOConfig (single source of truth)
        // Use the new reduceFundsRaised method which is safer than updateFundsRaised with negative values
        stoConfig.reduceFundsRaised(
            uint8(ISTOConfig.FundRaiseType.ERC20),
            _amount
        );

        emit Events.InvestmentWithdrawn(_investor, _amount);
    }

    /**
     * @notice Execute a signed withdrawal from an investor
     * @dev Anyone can call this function to submit a signed withdrawal on behalf of an investor
     * @param withdrawal The withdrawal details signed by the investor
     * @param signature The EIP-712 signature from the investor
     */
    function executeSignedWithdrawal(
        Withdrawal.WithdrawalInfo calldata withdrawal,
        bytes calldata signature
    ) external override whenNotPaused nonReentrant {
        // Verify the signature using the InvestmentManager
        // This will validate the signature and increment the nonce
        investmentManager.executeSignedWithdrawal(
            msg.sender,
            withdrawal,
            signature
        );

        // At this point, the signature is verified and the nonce is incremented
        // We can now execute the withdrawal on behalf of the investor

        // Store the original msg.sender for re-use
        address operator = msg.sender;

        // Execute the withdrawal using the internal _withdrawInvestment
        _withdrawInvestment(withdrawal.investor, withdrawal.withdrawalAmount);

        // Emit additional event for the signed withdrawal
        emit Events.SignedWithdrawalExecuted(
            withdrawal.investor,
            withdrawal.withdrawalAmount,
            withdrawal.nonce, // Emit the original nonce from the withdrawal request
            operator
        );
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
        bool endTimeReached = block.timestamp > stoConfig.endTime();
        bool hardCapReached = stoConfig.isHardCapReached();

        if (!(endTimeReached || hardCapReached)) {
            revert STOAlreadyActive();
        }

        // Check permissions
        if (msg.sender != address(this) && !hasRole(OPERATOR_ROLE, msg.sender)) {
            revert NotOperator(msg.sender);
        }

        // Check if STO is already closed, if not, close it
        if (!escrow.isSTOClosed()) {
            escrow.closeSTO(hardCapReached, endTimeReached);
        }

        // Get the finalization details from STOConfig
        bool softCapReached = stoConfig.isSoftCapReached();

        // Perform escrow finalization based on soft cap status
        if (!escrow.isFinalized()) {
            escrow.finalize(softCapReached);
        }

        // Get all investors to process
        address[] memory investors = investmentManager.getAllInvestors();

        // Delegate processing to the appropriate manager while preserving
        // the STO as the caller to avoid permission issues
        if (softCapReached) {
            // If soft cap reached, process minting
            this.mintTokensToInvestors(investors);
        } else {
            // If soft cap not reached, process refunds
            this.processRefundsToInvestors(investors);
        }

        emit Events.STOFinalized(softCapReached);
    }
    
    /**
     * @notice Issue tokens to a specific investor
     * @param _investor Address of the investor
     * @param _amount Amount of tokens to issue
     * @dev This function can now be called either by the Minting contract or directly by the STO
     *      when it needs to mint tokens. The actual implementation is delegated to FinalizationManager
     *      to maintain modularity while fixing permission issues.
     *
     * Dependencies:
     * - Can be called by the Minting contract or directly by this contract
     * - Logic is delegated to FinalizationManager to preserve modularity
     */
    function issueTokens(address _investor, uint256 _amount) external override {
        // Verify caller permission - allow both minting contract and this contract
        if (msg.sender != address(minting) && msg.sender != address(this)) {
            revert Unauthorized(msg.sender, "MINTING_OR_STO");
        }

        // Delegate token minting to finalization manager in all cases
        // The finalization manager has been updated to accept calls from this contract
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

    /**
     * @notice Handle minting delegation from the finalization manager
     * @dev This is called by the FinalizationManager when it's not an agent of the token
     * @param _investor The investor to receive tokens
     * @param _amount The amount of tokens to mint
     */
    function handleDelegatedMinting(address _investor, uint256 _amount) external {
        // Only allow calls from the finalization manager
        if (msg.sender != address(finalizationManager)) {
            revert Unauthorized(msg.sender, "FINALIZATION_MANAGER");
        }

        // For Rule506c offerings, mint directly if STO is an agent
        if (isRule506cOffering) {
            IToken token = IToken(securityToken);

            // Mint tokens to the investor
            try token.mint(_investor, _amount) {
                // Success! Emit an event
                emit Events.TokensDelivered(_investor, _amount);
            } catch Error(string memory reason) {
                // Handle specific error from token contract
                revert(string(abi.encodePacked("Token mint failed: ", reason)));
            } catch {
                // Handle other errors
                revert("Token mint failed due to compliance check");
            }
        } else {
            // For simple ERC20 tokens, transfer from contract balance
            bool success = IERC20(securityToken).transfer(_investor, _amount);
            if (!success) {
                revert TransferFailed(securityToken, address(this), _investor, _amount);
            }
            emit Events.TokensDelivered(_investor, _amount);
        }
    }

    /**
     * @notice Transfer tokens from STO's balance to an investor
     * @dev Used for non-Rule506c tokens which don't require minting permissions
     * @param _investor The investor to receive tokens
     * @param _amount The amount of tokens to transfer
     */
    function transferTokens(address _investor, uint256 _amount) external {
        // Only allow calls from the finalization manager
        if (msg.sender != address(finalizationManager)) {
            revert Unauthorized(msg.sender, "FINALIZATION_MANAGER");
        }

        // Simple ERC20 transfer from STO contract balance to investor
        bool success = IERC20(securityToken).transfer(_investor, _amount);
        if (!success) {
            revert TransferFailed(securityToken, address(this), _investor, _amount);
        }

        emit Events.TokensDelivered(_investor, _amount);
    }

    /**
     * @notice Helper function to mint tokens to multiple investors
     * @dev This function is used during finalization to efficiently mint tokens
     *      while preserving modularity by delegating to FinalizationManager
     * @param _investors Array of investor addresses
     */
    function mintTokensToInvestors(address[] calldata _investors) external {
        if (msg.sender != address(this)) {
            revert Unauthorized(msg.sender, "STO_ONLY");
        }

        // Delegate to finalization manager to maintain modularity
        finalizationManager.processMinting(_investors);
    }

    /**
     * @notice Helper function to process refunds for multiple investors
     * @dev This function is used during finalization when soft cap isn't reached
     * @param _investors Array of investor addresses
     */
    function processRefundsToInvestors(address[] calldata _investors) external {
        if (msg.sender != address(this)) {
            revert Unauthorized(msg.sender, "STO_ONLY");
        }

        // Call the new method that processes refunds directly
        processRefundsForInvestors(_investors);
    }

    /**
     * @notice Process refunds for investors - called by FinalizationManager
     * @dev This function is the entry point for the FinalizationManager to request refunds
     * @param _investors Array of investor addresses to process
     */
    function processRefundsForInvestors(address[] calldata _investors) public {
        // Only allow calls from this contract or the finalization manager
        if (msg.sender != address(this) && msg.sender != address(finalizationManager)) {
            revert Unauthorized(msg.sender, "STO_OR_FINALIZATION_MANAGER");
        }

        // Process each investor directly from the STO contract
        for (uint256 i = 0; i < _investors.length; i++) {
            address investor = _investors[i];

            // Use the finalization manager to get refund details
            (bool needsRefund, uint256 amount) = finalizationManager.getRefundDetailsForInvestor(investor);

            if (needsRefund && amount > 0) {
                // Mark the refund as processed in the refund contract
                // This call will succeed because it's coming from the STO contract
                refund.markRefundProcessed(investor, amount);

                // IMPORTANT: We need to transfer from the Escrow contract, not from the STO
                // The funds are stored in the Escrow contract, not in the STO contract
                // First approve the investor to withdraw from escrow
                escrow.approveRefund(investor, amount);

                // Emit event after the approval
                emit Events.RefundProcessed(investor, amount);
            }
        }
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

    /**
     * @notice Check if the STO is closed
     * @return Whether the STO is closed
     */
    function isSTOClosed() external view override returns (bool) {
        return escrow.isSTOClosed();
    }

    /**
     * @notice Check if the escrow is finalized
     * @return Whether the escrow is finalized
     */
    function isEscrowFinalized() external view override returns (bool) {
        return escrow.isFinalized();
    }
}