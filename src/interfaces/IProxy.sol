// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Proxy interface
 * @dev Interface for the proxy pattern that forwards calls to implementation
 */
interface IProxy {
    /**
     * @dev Upgrade the implementation address
     * @param _newImplementation Address of the new implementation
     */
    function upgradeTo(address _newImplementation) external;
    
    /**
     * @dev Get the current implementation address
     * @return Address of the current implementation
     */
    function implementation() external view returns (address);
    
    /**
     * @dev Get the current admin address
     * @return Address of the current admin
     */
    function admin() external view returns (address);
    
    /**
     * @dev Change the admin address
     * @param _newAdmin Address of the new admin
     */
    function changeAdmin(address _newAdmin) external;
}