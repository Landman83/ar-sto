// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@ar-security-token/lib/st-identity-registry/src/interfaces/IAttributeRegistry.sol";
import "@ar-security-token/src/interfaces/IToken.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// Import local libraries for conflict prevention
import "../libraries/Attributes.sol";

/**
 * @title VerificationManager
 * @notice Manages investor verification for Security Token Offerings
 * @dev Integrates with attribute registry for compliance checks
 */
contract VerificationManager is ReentrancyGuard {
    // Reference to the main STO contract
    address public stoContract;
    
    // The security token being sold
    address public securityToken;
    
    // Attribute registry for compliance verification
    IAttributeRegistry public attributeRegistry;
    
    // Flag indicating if this is a Rule506c compliant offering
    bool public isRule506cOffering;
    
    // Verification status mapping for investors
    mapping(address => bool) public isVerified;
    
    // Addresses waiting for verification
    address[] private _pendingVerifications;
    mapping(address => bool) private _isPending;
    
    // Mapping of address to custom verification data (for manual verification)
    mapping(address => bytes32) public verificationData;
    
    // Events
    event InvestorVerified(address indexed investor, bool status);
    event VerificationRequested(address indexed investor, bytes32 data);
    event AttributeRegistryUpdated(address indexed previousRegistry, address indexed newRegistry);
    
    /**
     * @notice Constructor
     * @param _stoContract Address of the main STO contract
     * @param _securityToken Address of the security token
     * @param _isRule506c Flag indicating if this is a Rule506c compliant offering
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
        
        // Try to get the attribute registry from the security token
        _initializeAttributeRegistry();
    }
    
    /**
     * @notice Modifier to ensure only the STO contract can call
     */
    modifier onlySTOContract() {
        require(msg.sender == stoContract, "Only STO contract can call");
        _;
    }
    
    /**
     * @notice Initialize the attribute registry from security token
     */
    function _initializeAttributeRegistry() internal {
        // Try to get the attribute registry from the security token
        // Use a try/catch since the function might not exist or revert
        try IToken(securityToken).attributeRegistry() returns (IAttributeRegistry registry) {
            if (address(registry) != address(0)) {
                attributeRegistry = registry;
            }
        } catch {
            // Attribute registry will be set manually later
        }
    }
    
    /**
     * @notice Set the attribute registry address
     * @param _attributeRegistry The address of the attribute registry
     */
    function setAttributeRegistry(address _attributeRegistry) external onlySTOContract {
        require(_attributeRegistry != address(0), "Attribute registry cannot be zero");
        address oldRegistry = address(attributeRegistry);
        attributeRegistry = IAttributeRegistry(_attributeRegistry);
        emit AttributeRegistryUpdated(oldRegistry, _attributeRegistry);
    }
    
    /**
     * @notice Check if an investor is verified
     * @param _investor The address of the investor to check
     * @return Whether the investor is verified
     */
    function isInvestorVerified(address _investor) external view returns (bool) {
        if (!isRule506cOffering) {
            // Non-regulated offerings don't require verification
            return true;
        }
        
        // First check our local cache
        if (isVerified[_investor]) {
            return true;
        }
        
        // If not in cache, check the attribute registry
        if (address(attributeRegistry) != address(0)) {
            return _checkAttributeRegistry(_investor);
        }
        
        return false;
    }
    
    /**
     * @notice Check if an investor has the required attributes
     * @param _investor The address of the investor to check
     * @return Whether the investor has the required attributes
     */
    function _checkAttributeRegistry(address _investor) internal view returns (bool) {
        try attributeRegistry.hasAttribute(_investor, Attributes.ACCREDITED_INVESTOR) returns (bool hasAttribute) {
            return hasAttribute;
        } catch {
            return false;
        }
    }
    
    /**
     * @notice Add an investor to the verified list (manual verification)
     * @param _investor The address of the investor to verify
     */
    function verifyInvestor(address _investor) external onlySTOContract {
        require(_investor != address(0), "Investor address cannot be zero");
        
        if (!isVerified[_investor]) {
            isVerified[_investor] = true;
            
            // Remove from pending list if present
            if (_isPending[_investor]) {
                _isPending[_investor] = false;
            }
            
            emit InvestorVerified(_investor, true);
        }
    }
    
    /**
     * @notice Add multiple investors to the verified list
     * @param _investors Array of investor addresses to verify
     */
    function batchVerifyInvestors(address[] calldata _investors) external onlySTOContract {
        for (uint256 i = 0; i < _investors.length; i++) {
            address investor = _investors[i];
            if (investor != address(0) && !isVerified[investor]) {
                isVerified[investor] = true;
                
                // Remove from pending list if present
                if (_isPending[investor]) {
                    _isPending[investor] = false;
                }
                
                emit InvestorVerified(investor, true);
            }
        }
    }
    
    /**
     * @notice Remove an investor from the verified list
     * @param _investor The address of the investor to unverify
     */
    function unverifyInvestor(address _investor) external onlySTOContract {
        require(_investor != address(0), "Investor address cannot be zero");
        
        if (isVerified[_investor]) {
            isVerified[_investor] = false;
            emit InvestorVerified(_investor, false);
        }
    }
    
    /**
     * @notice Request verification with custom data
     * @param _investor The address of the investor requesting verification
     * @param _data Additional verification data (e.g., document hash)
     */
    function requestVerification(address _investor, bytes32 _data) external {
        // Self-verification or STO contract can request
        require(msg.sender == _investor || msg.sender == stoContract, "Unauthorized");
        require(_investor != address(0), "Investor address cannot be zero");
        
        // Store verification data
        verificationData[_investor] = _data;
        
        // Add to pending list if not already there
        if (!_isPending[_investor] && !isVerified[_investor]) {
            _pendingVerifications.push(_investor);
            _isPending[_investor] = true;
        }
        
        emit VerificationRequested(_investor, _data);
    }
    
    /**
     * @notice Get all pending verification requests
     * @return Array of addresses with pending verification
     */
    function getPendingVerifications() external view returns (address[] memory) {
        return _pendingVerifications;
    }
    
    /**
     * @notice Check if an investor has a pending verification
     * @param _investor The address of the investor to check
     * @return Whether the investor has a pending verification
     */
    function hasPendingVerification(address _investor) external view returns (bool) {
        return _isPending[_investor];
    }
    
    /**
     * @notice Update the pending verification list to remove verified investors
     * @dev This is a maintenance function to clean up the pending list
     */
    function cleanupPendingList() external onlySTOContract {
        uint256 count = _pendingVerifications.length;
        address[] memory stillPending = new address[](count);
        uint256 newCount = 0;
        
        for (uint256 i = 0; i < count; i++) {
            address investor = _pendingVerifications[i];
            if (_isPending[investor] && !isVerified[investor]) {
                stillPending[newCount] = investor;
                newCount++;
            } else {
                _isPending[investor] = false;
            }
        }
        
        // Create a new array with only the still pending verifications
        _pendingVerifications = new address[](newCount);
        for (uint256 i = 0; i < newCount; i++) {
            _pendingVerifications[i] = stillPending[i];
        }
    }
}

// Interface ITokenRegistry replaced with IToken imported from ar-security-token