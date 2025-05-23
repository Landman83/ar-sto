// Only allows KYC verified users to participate in STOs

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "../interfaces/ICompliance.sol";
import "../interfaces/IAgentRole.sol";
import "../interfaces/IVerificationManager.sol";
import "@ar-security-token/src/interfaces/IToken.sol";
import "@ar-security-token/lib/st-identity-registry/src/interfaces/IAttributeRegistry.sol";
import "@ar-security-token/lib/st-identity-registry/src/libraries/Attributes.sol";

/**
 * @title Compliance
 * @notice Implementation of token compliance checks
 */
contract Compliance is Ownable, ICompliance {
    constructor(address initialOwner) Ownable(initialOwner) {}
    
    /**
     * @notice Check if a token is a TREX token
     * @param token The address of the token to check
     * @return True if the token is a TREX token, false otherwise
     */
    function isTREX(address token) public view override returns (bool) {
        try IToken(token).attributeRegistry() returns (IAttributeRegistry _ar) {
            if (address(_ar) != address(0)) {
                return true;
            }
            return false;
        }
        catch {
            return false;
        }
    }
    
    /**
     * @notice Check if a user is an agent of a TREX token
     * @param token The address of the token to check
     * @param user The address of the user to check
     * @return True if the user is an agent of the token, false otherwise
     */
    function isTREXAgent(address token, address user) public view override returns (bool) {
        if (isTREX(token)){
            return IAgentRole(token).isAgent(user);
        }
        return false;
    }
    
    /**
     * @notice Check if a user is the owner of a TREX token
     * @param token The address of the token to check
     * @param user The address of the user to check
     * @return True if the user is the owner of the token, false otherwise
     */
    function isTREXOwner(address token, address user) public view override returns (bool) {
        if (isTREX(token)){
            return Ownable(token).owner() == user;
        }
        return false;
    }
    
    /**
     * @notice Check if an investor can buy tokens in a Rule506c offering
     * @param token The address of the token
     * @param investor The address of the investor
     * @param verificationManager Optional verification manager address
     * @param isRule506cOffering Whether this is a Rule506c offering
     * @return True if the investor can buy tokens, false otherwise
     */
    function canInvestorBuy(
        address token, 
        address investor, 
        address verificationManager,
        bool isRule506cOffering
    ) public view override returns (bool) {
        // For non-regulated offerings, allow any address to buy
        if (!isRule506cOffering) {
            return true;
        }
        
        // If verification manager is set and valid, use it
        if (verificationManager != address(0)) {
            try IVerificationManager(verificationManager).isInvestorVerified(investor) returns (bool isVerified) {
                return isVerified;
            } catch {
                // Fallback to direct attribute check if verification manager fails
            }
        }
        
        // Try direct attribute registry check
        try IToken(token).attributeRegistry() returns (IAttributeRegistry attributeRegistry) {
            try attributeRegistry.hasAttribute(investor, Attributes.ACCREDITED_INVESTOR) returns (bool hasAttribute) {
                return hasAttribute;
            } catch {
                return false;
            }
        } catch {
            return false;
        }
    }
}
