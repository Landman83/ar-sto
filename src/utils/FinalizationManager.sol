// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@ar-security-token/src/interfaces/IToken.sol";
import "../libraries/Events.sol";
import "./Escrow.sol";
import "./Minting.sol";
import "./Refund.sol";
import "./STOConfig.sol";

/**
 * @title FinalizationManager
 * @notice Manages the finalization process for Security Token Offerings
 */
contract FinalizationManager is ReentrancyGuard {
    // Reference to the main STO contract
    address public stoContract;
    
    // The security token being sold
    address public securityToken;
    
    // The escrow contract
    Escrow public escrow;
    
    // The minting contract
    Minting public minting;
    
    // The refund contract
    Refund public refund;
    
    // Flag indicating if this is a Rule506c compliant offering
    bool public isRule506cOffering;
    
    // Configuration contract for STO parameters
    STOConfig public stoConfig;
    
    // Events
    event FinalizationCompleted(
        bool softCapReached,
        uint256 totalTokensSold,
        uint256 timestamp
    );
    
    event TokensDelivered(
        address indexed investor,
        uint256 amount,
        bool byOwner
    );
    
    /**
     * @notice Constructor
     * @param _stoContract Address of the main STO contract
     * @param _securityToken Address of the security token
     * @param _escrow Address of the escrow contract
     * @param _minting Address of the minting contract
     * @param _refund Address of the refund contract
     * @param _isRule506c Flag indicating if this is a Rule506c compliant offering
     */
    constructor(
        address _stoContract,
        address _securityToken,
        address _escrow,
        address _minting,
        address _refund,
        bool _isRule506c
    ) {
        require(_stoContract != address(0), "STO contract cannot be zero");
        require(_securityToken != address(0), "Security token cannot be zero");
        require(_escrow != address(0), "Escrow cannot be zero");
        require(_minting != address(0), "Minting cannot be zero");
        require(_refund != address(0), "Refund cannot be zero");
        
        stoContract = _stoContract;
        securityToken = _securityToken;
        escrow = Escrow(_escrow);
        minting = Minting(_minting);
        refund = Refund(_refund);
        isRule506cOffering = _isRule506c;
    }
    
    /**
     * @notice Set the STOConfig contract 
     * @param _stoConfig Address of the STOConfig contract
     * @dev This connects the FinalizationManager to the authoritative configuration source
     */
    function setSTOConfig(address _stoConfig) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(_stoConfig != address(0), "STOConfig cannot be zero");
        
        // If we already had a configuration contract, don't replace it
        if (address(stoConfig) != address(0)) {
            require(address(stoConfig) == _stoConfig, "Config already set");
            return;
        }
        
        stoConfig = STOConfig(_stoConfig);
    }
    
    /**
     * @notice Finalize the offering
     * @param _endTime The end time of the offering
     * @param _hardCapReached Whether the hard cap has been reached
     * @param _investors Array of all investor addresses
     * @return softCapReached Whether the soft cap was reached
     */
    function finalize(
        uint256 _endTime,
        bool _hardCapReached,
        address[] calldata _investors
    ) 
        external 
        nonReentrant
        returns (bool softCapReached) 
    {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(block.timestamp > _endTime || _hardCapReached, "Offering not yet ended and hard cap not reached");
        
        // Close the STO if not already closed
        if (!escrow.isSTOClosed()) {
            escrow.closeSTO(_hardCapReached, block.timestamp > _endTime);
        }
        
        // Finalize the escrow if not already finalized
        if (!escrow.isFinalized()) {
            // Check if soft cap is reached, preferring STOConfig if available
            if (address(stoConfig) != address(0)) {
                softCapReached = stoConfig.isSoftCapReached();
            } else {
                softCapReached = escrow.isSoftCapReached();
            }
            
            // Finalize the escrow with soft cap status
            escrow.finalize(softCapReached);
            
            // If soft cap is reached, automatically mint tokens to all investors
            if (softCapReached) {
                _mintTokensToAllInvestors(_investors);
            } else {
                // If soft cap is not reached, automatically process refunds for all investors
                _processRefundsForAllInvestors(_investors);
            }
            
            emit FinalizationCompleted(softCapReached, escrow.getTotalTokensSold(), block.timestamp);
        } else {
            // Get soft cap status from the most authoritative source
            if (address(stoConfig) != address(0)) {
                softCapReached = stoConfig.isSoftCapReached();
            } else {
                softCapReached = escrow.isSoftCapReached();
            }
        }
        
        return softCapReached;
    }
    
    /**
     * @notice Process refunds for all investors when soft cap is not reached
     * @param _investors Array of investor addresses
     */
    function _processRefundsForAllInvestors(address[] calldata _investors) internal {
        // Call back to the STO contract to handle the refunds
        // This ensures that calls to the Refund contract come directly from the STO
        (bool success,) = stoContract.call(
            abi.encodeWithSignature(
                "processRefundsForInvestors(address[])",
                _investors
            )
        );

        // If the call fails, revert with an error message
        if (!success) {
            revert("Failed to process refunds through STO");
        }
    }

    /**
     * @notice Get refund details for an investor
     * @param _investor Address of the investor
     * @return needsRefund Whether the investor needs a refund
     * @return amount Amount to refund
     */
    function getRefundDetailsForInvestor(address _investor) external view returns (bool needsRefund, uint256 amount) {
        // Skip if investor has already claimed refund
        if (refund.hasClaimedRefund(_investor)) {
            return (false, 0);
        }

        // Get investment amount from escrow
        uint256 investmentAmount = escrow.getInvestment(_investor);

        // Return true and the amount if a refund is needed
        return (investmentAmount > 0, investmentAmount);
    }

    /**
     * @notice Process refunds for all investors
     * @param _investors Array of investor addresses
     */
    function processRefunds(address[] calldata _investors) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(escrow.isFinalized(), "Escrow not finalized");
        require(!stoConfig.isSoftCapReached(), "Soft cap reached, refunds not needed");

        _processRefundsForAllInvestors(_investors);
    }

    /**
     * @notice Get list of investors that need refunds
     * @return Array of investor addresses that need refunds
     * @dev This is a placeholder implementation - not used in the actual code flow
     */
    function getInvestorsNeedingRefunds() external view returns (address[] memory) {
        // This method would normally return all investors that need refunds
        // For now, we return an empty array as it's not needed for our implementation
        return new address[](0);
    }

    /**
     * @notice Process refund for a single investor
     * @param _investor The investor address to process refund for
     * @param _amount The amount to refund
     */
    function processRefund(address _investor, uint256 _amount) external {
        require(msg.sender == stoContract, "Only STO contract can call");

        // Mark the refund in the refund contract if it hasn't been claimed yet
        if (!refund.hasClaimedRefund(_investor)) {
            refund.markRefundProcessed(_investor, _amount);
        }
    }

    /**
     * @notice Mint tokens to all investors
     * @param _investors Array of investor addresses
     */
    function _mintTokensToAllInvestors(address[] calldata _investors) internal {
        // Let the minting contract handle the token issuance flow
        // This ensures that calls to issueTokens come from the minting contract
        minting.batchMintAndDeliverTokens(_investors);
    }

    /**
     * @notice Public function to process minting for all investors
     * @param _investors Array of investor addresses
     */
    function processMinting(address[] calldata _investors) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(escrow.isFinalized(), "Escrow not finalized");
        require(stoConfig.isSoftCapReached(), "Soft cap not reached, minting not possible");

        _mintTokensToAllInvestors(_investors);

        emit FinalizationCompleted(true, escrow.getTotalTokensSold(), block.timestamp);
    }
    
    /**
     * @notice Issue tokens to a specific investor
     * @param _investor Address of the investor
     * @param _amount Amount of tokens to issue
     */
    function issueTokens(address _investor, uint256 _amount) external {
        // Allow calls from either minting contract or STO contract
        require(msg.sender == address(minting) || msg.sender == stoContract,
               "Only minting or STO contract can call this function");

        if (isRule506cOffering) {
            // Get the token interface
            IToken token = IToken(securityToken);

            // Check if this contract is registered as an agent
            bool isSTOAgent = false;
            // IToken interface doesn't have isAgent function, so use a try/catch with a custom call
            (bool success, bytes memory result) = address(token).call(
                abi.encodeWithSignature("isAgent(address)", address(this))
            );
            if (success && result.length > 0) {
                // Decode the result if the call was successful
                (isSTOAgent) = abi.decode(result, (bool));
            } else {
                // If the call fails, assume we're not an agent
                isSTOAgent = false;
            }

            if (isSTOAgent) {
                // If registered as an agent, mint directly with try/catch to handle compliance errors
                try token.mint(_investor, _amount) {
                    emit TokensDelivered(_investor, _amount, false);
                } catch Error(string memory reason) {
                    // Handle specific error messages from the token contract
                    revert(string(abi.encodePacked("Token mint failed: ", reason)));
                } catch {
                    // Handle other errors
                    revert("Token mint failed due to compliance check");
                }
            } else {
                // If not a registered agent, delegate minting to the STO contract
                // which should be handled by the owner
                (bool success2,) = stoContract.call(
                    abi.encodeWithSignature(
                        "handleDelegatedMinting(address,uint256)",
                        _investor,
                        _amount
                    )
                );
                require(success2, "Failed to delegate minting");
            }
        } else {
            // For simple ERC20 tokens, transfer from STO contract's balance
            // This assumes the STO contract has been allocated tokens to distribute
            (bool success,) = stoContract.call(
                abi.encodeWithSignature(
                    "transferTokens(address,uint256)",
                    _investor,
                    _amount
                )
            );
            require(success, "Token transfer failed");
            emit TokensDelivered(_investor, _amount, false);
        }
    }
    
    /**
     * @notice Helper function for the owner to manually mint tokens to an investor
     * @param _investor The address of the investor to receive tokens
     * @param _amount The amount of tokens to mint
     * @param _owner The address of the owner performing the minting
     */
    function ownerMintTokens(address _investor, uint256 _amount, address _owner) external {
        require(msg.sender == stoContract, "Only STO contract can call");
        require(isRule506cOffering, "Only applicable for Rule506c offerings");
        
        // Verify the investor should receive these tokens
        require(escrow.getTokenAllocation(_investor) >= _amount, "Allocation mismatch");
        require(!minting.hasClaimedTokens(_investor), "Tokens already claimed");
        
        // Mark tokens as claimed in the minting contract
        minting.markTokensAsClaimed(_investor);
        
        // Owner will mint tokens directly to the investor
        IToken token = IToken(securityToken);
        
        try token.mint(_investor, _amount) {
            emit TokensDelivered(_investor, _amount, true);
        } catch Error(string memory reason) {
            // Revert with the specific error from the token contract
            revert(string(abi.encodePacked("Token mint failed: ", reason)));
        } catch {
            // Handle other errors
            revert("Token mint failed due to compliance check");
        }
    }
    
    /**
     * @notice Check if an investor has received their tokens
     * @param _investor Address of the investor
     * @return Whether the investor has received tokens
     */
    function hasReceivedTokens(address _investor) external view returns (bool) {
        return minting.hasClaimedTokens(_investor);
    }
    
    /**
     * @notice Check if an investor has claimed their refund
     * @param _investor Address of the investor
     * @return Whether the investor has claimed a refund
     */
    function hasClaimedRefund(address _investor) external view returns (bool) {
        return refund.hasClaimedRefund(_investor);
    }
    
    /**
     * @notice Check if soft cap was reached
     * @return Whether the soft cap was reached
     * @dev This is the authoritative source for the soft cap status.
     *      It uses STOConfig if available, falling back to escrow otherwise.
     */
    function isSoftCapReached() external view returns (bool) {
        if (address(stoConfig) != address(0)) {
            return stoConfig.isSoftCapReached();
        }
        return escrow.isSoftCapReached();
    }
    
    /**
     * @notice Check if the offering has been finalized
     * @return Whether the offering has been finalized
     * @dev Returns the finalization status directly from the escrow
     */
    function isFinalized() external view returns (bool) {
        return escrow.isFinalized();
    }
}