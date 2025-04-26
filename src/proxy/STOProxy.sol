// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../interfaces/IProxy.sol";

/**
 * @title STO Proxy
 * @dev Proxy contract for STO implementations that forwards calls to the implementation contract
 * and allows for upgradeable STO contracts without changing storage
 */
contract STOProxy is IProxy {
    // Storage positions for proxy variables
    bytes32 private constant IMPLEMENTATION_POSITION = keccak256("com.sto.proxy.implementation");
    bytes32 private constant ADMIN_POSITION = keccak256("com.sto.proxy.admin");
    
    // Event emitted when implementation is upgraded
    event Upgraded(address indexed implementation);
    
    /**
     * @dev Constructor that sets the STO implementation address and forwards initialization to the implementation
     * @param _implementation Address of the STO implementation
     * @param _securityToken Address of the security token
     * @param _isRule506c Whether this is a Rule 506c compliant offering
     * @param _owner Address that should own the STO (typically the deployer, not the factory)
     */
    constructor(address _implementation, address _securityToken, bool _isRule506c, address _owner) {
        require(_implementation != address(0), "Implementation cannot be zero address");
        require(_owner != address(0), "Owner cannot be zero address");
        
        // Set the implementation address
        _setImplementation(_implementation);
        
        // Set the admin (msg.sender)
        _setAdmin(msg.sender);
        
        // Initialize the proxy by delegating to the implementation's init function
        // instead of trying to call a constructor (which can't be called via delegatecall)
        (bool success, bytes memory data) = _implementation.delegatecall(
            abi.encodeWithSignature("initialize(address,bool,address)", _securityToken, _isRule506c, _owner)
        );
        
        // If initialization fails, revert with reason if available
        if (!success) {
            assembly {
                revert(add(data, 32), mload(data))
            }
        }
    }
    
    /**
     * @dev Upgrade the implementation address
     * @param _newImplementation Address of the new implementation
     */
    function upgradeTo(address _newImplementation) external {
        require(msg.sender == _admin(), "Only admin can upgrade implementation");
        require(_newImplementation != address(0), "New implementation cannot be zero address");
        
        _setImplementation(_newImplementation);
        emit Upgraded(_newImplementation);
    }
    
    /**
     * @dev Get the current implementation address
     * @return Address of the current implementation
     */
    function implementation() external view returns (address) {
        return _implementation();
    }
    
    /**
     * @dev Get the current admin address
     * @return Address of the current admin
     */
    function admin() external view returns (address) {
        return _admin();
    }
    
    /**
     * @dev Change the admin address
     * @param _newAdmin Address of the new admin
     */
    function changeAdmin(address _newAdmin) external {
        require(msg.sender == _admin(), "Only admin can change admin");
        require(_newAdmin != address(0), "New admin cannot be zero address");
        
        _setAdmin(_newAdmin);
    }
    
    /**
     * @dev Fallback function that delegates all calls to the implementation
     */
    fallback() external payable {
        _delegate(_implementation());
    }
    
    /**
     * @dev Receive function to accept ETH
     */
    receive() external payable {
        _delegate(_implementation());
    }
    
    /**
     * @dev Read implementation address from storage
     * @return implementation_ Address of the implementation
     */
    function _implementation() internal view returns (address implementation_) {
        bytes32 position = IMPLEMENTATION_POSITION;
        assembly {
            implementation_ := sload(position)
        }
    }
    
    /**
     * @dev Set implementation address in storage
     * @param _implementation Address of the implementation
     */
    function _setImplementation(address _implementation) internal {
        bytes32 position = IMPLEMENTATION_POSITION;
        assembly {
            sstore(position, _implementation)
        }
    }
    
    /**
     * @dev Read admin address from storage
     * @return admin_ Address of the admin
     */
    function _admin() internal view returns (address admin_) {
        bytes32 position = ADMIN_POSITION;
        assembly {
            admin_ := sload(position)
        }
    }
    
    /**
     * @dev Set admin address in storage
     * @param _admin Address of the admin
     */
    function _setAdmin(address _admin) internal {
        bytes32 position = ADMIN_POSITION;
        assembly {
            sstore(position, _admin)
        }
    }
    
    /**
     * @dev Delegate the current call to implementation
     * @param _implementation Address of the implementation to delegate to
     */
    function _delegate(address _implementation) internal {
        assembly {
            // Copy msg.data. We take full control of memory in this inline assembly
            // block because it will not return to Solidity code. We overwrite the
            // Solidity scratch pad at memory position 0.
            calldatacopy(0, 0, calldatasize())
            
            // Call the implementation.
            // out and outsize are 0 because we don't know the size yet.
            let result := delegatecall(gas(), _implementation, 0, calldatasize(), 0, 0)
            
            // Copy the returned data.
            returndatacopy(0, 0, returndatasize())
            
            switch result
            // delegatecall returns 0 on error.
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }
}