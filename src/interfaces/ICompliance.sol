// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title ICompliance
 * @notice Interface for token compliance checks
 */
interface ICompliance {
    /**
     * @notice Check if a token is a TREX token
     * @param token The address of the token to check
     * @return True if the token is a TREX token, false otherwise
     */
    function isTREX(address token) external view returns (bool);
    
    /**
     * @notice Check if a user is an agent of a TREX token
     * @param token The address of the token to check
     * @param user The address of the user to check
     * @return True if the user is an agent of the token, false otherwise
     */
    function isTREXAgent(address token, address user) external view returns (bool);
    
    /**
     * @notice Check if a user is the owner of a TREX token
     * @param token The address of the token to check
     * @param user The address of the user to check
     * @return True if the user is the owner of the token, false otherwise
     */
    function isTREXOwner(address token, address user) external view returns (bool);
    
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
    ) external view returns (bool);
}
