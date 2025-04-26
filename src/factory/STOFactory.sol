// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../proxy/STOProxy.sol";
import "./STOAuxiliaryFactory.sol";
import "../CappedSTO.sol";
import "../interfaces/ISTO.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title STO Factory
 * @dev Factory for deploying complete STO setups including auxiliary contracts
 */
contract STOFactory is Ownable {
    // STO implementation contract
    address public stoImplementation;
    
    // Auxiliary Factory contract
    STOAuxiliaryFactory public auxiliaryFactory;
    
    // Event for tracking STO deployments
    event STODeployed(
        address indexed sto,
        address indexed securityToken,
        address indexed owner,
        bool isRule506c,
        // Auxiliary contract addresses
        address fixedPrice,
        address minting,
        address refund,
        address fees,
        address escrow
    );
    
    // Last deployed STO information for easy retrieval
    struct STODeploymentInfo {
        address sto;
        address securityToken;
        address fixedPrice;
        address minting;
        address refund;
        address fees;
        address escrow;
    }
    
    // Deployment parameters structure to reduce stack usage
    struct DeploymentParams {
        address securityToken;
        bool isRule506c;
        uint256 startTime;
        uint256 endTime;
        uint256 hardCap;
        uint256 softCap;
        uint256 rate;
        address payable fundsReceiver;
        address investmentToken;
        uint256 feeRate;
        address feeWallet;
        address owner;
    }
    
    // Mapping of deployment ID to deployment info
    mapping(bytes32 => STODeploymentInfo) public deployments;
    
    // Array to track all deployment IDs
    bytes32[] public allDeploymentIds;
    
    /**
     * @dev Constructor to set up the STO factory
     * @param _stoImplementation Address of the STO implementation contract
     * @param _auxiliaryFactory Address of the auxiliary factory contract
     */
    constructor(address _stoImplementation, address _auxiliaryFactory) Ownable(msg.sender) {
        require(_stoImplementation != address(0), "STO implementation cannot be zero");
        require(_auxiliaryFactory != address(0), "Auxiliary factory cannot be zero");
        
        stoImplementation = _stoImplementation;
        auxiliaryFactory = STOAuxiliaryFactory(_auxiliaryFactory);
    }
    
    /**
     * @dev Deploy STO with individual parameters (convenience function)
     * This function exists for backward compatibility with existing scripts
     */
    function deploySTOWithParams(
        address _securityToken,
        bool _isRule506c,
        uint256 _startTime,
        uint256 _endTime,
        uint256 _hardCap,
        uint256 _softCap,
        uint256 _rate,
        address payable _fundsReceiver,
        address _investmentToken,
        uint256 _feeRate,
        address _feeWallet,
        address _owner
    ) public returns (bytes32 deploymentId, address stoAddress) {
        DeploymentParams memory params = DeploymentParams({
            securityToken: _securityToken,
            isRule506c: _isRule506c,
            startTime: _startTime,
            endTime: _endTime,
            hardCap: _hardCap,
            softCap: _softCap,
            rate: _rate,
            fundsReceiver: _fundsReceiver,
            investmentToken: _investmentToken,
            feeRate: _feeRate,
            feeWallet: _feeWallet,
            owner: _owner
        });
        
        return _deploySTO(params);
    }
    
    /**
     * @dev Deploy a complete STO with all auxiliary contracts
     * @param _params All deployment parameters packed in a struct
     * @return deploymentId A unique ID for this deployment
     * @return stoAddress Address of the deployed STO
     */
    function deploySTO(
        DeploymentParams calldata _params
    ) external returns (bytes32 deploymentId, address stoAddress) {
        return _deploySTO(_params);
    }
    
    /**
     * @dev Internal implementation of STO deployment
     */
    function _deploySTO(
        DeploymentParams memory _params
    ) internal returns (bytes32 deploymentId, address stoAddress) {
        _validateDeploymentParams(_params);
        
        // 1. Deploy STO proxy with implementation, passing the proper owner
        stoAddress = _deployStoProxy(_params.securityToken, _params.isRule506c, _params.owner);
        
        // 2. Deploy all auxiliary contracts and initialize STO
        (
            address fixedPrice,
            address minting,
            address refund,
            address fees,
            address escrow
        ) = _deployAndInitializeContracts(stoAddress, _params);
        
        // 3. Set up tracking - ownership transfer is handled in the initialize function
        // Skip Ownable transferOwnership call since it's not properly delegated through the proxy
        
        // 4. Generate a deployment ID and store information
        deploymentId = keccak256(abi.encodePacked(
            _params.owner,
            _params.securityToken,
            block.timestamp
        ));
        
        // Store deployment information
        _storeDeploymentInfo(
            deploymentId, 
            stoAddress, 
            _params.securityToken, 
            fixedPrice, 
            minting, 
            refund, 
            fees, 
            escrow
        );
        
        // 5. Emit deployment event
        emit STODeployed(
            stoAddress,
            _params.securityToken,
            _params.owner,
            _params.isRule506c,
            fixedPrice,
            minting,
            refund,
            fees,
            escrow
        );
        
        return (deploymentId, stoAddress);
    }
    
    /**
     * @dev Validate deployment parameters
     */
    function _validateDeploymentParams(DeploymentParams memory _params) private view {
        require(_params.securityToken != address(0), "Security token cannot be zero");
        require(_params.fundsReceiver != address(0), "Funds receiver cannot be zero");
        require(_params.investmentToken != address(0), "Investment token cannot be zero");
        require(_params.owner != address(0), "Owner cannot be zero");
        require(_params.startTime > block.timestamp, "Start time must be in the future");
        require(_params.endTime > _params.startTime, "End time must be after start time");
        require(_params.hardCap > 0, "Hard cap must be greater than zero");
        require(_params.softCap > 0, "Soft cap must be greater than zero");
        require(_params.hardCap >= _params.softCap, "Hard cap must be greater than soft cap");
        require(_params.rate > 0, "Rate must be greater than zero");
    }
    
    /**
     * @dev Deploy STO proxy
     */
    function _deployStoProxy(address _securityToken, bool _isRule506c, address _owner) private returns (address) {
        // Create proxy with proper owner (the deployer, not the factory)
        STOProxy stoProxy = new STOProxy(stoImplementation, _securityToken, _isRule506c, _owner);
        return address(stoProxy);
    }
    
    /**
     * @dev Deploy auxiliary contracts and initialize STO
     */
    function _deployAndInitializeContracts(
        address _stoAddress, 
        DeploymentParams memory _params
    ) private returns (
        address fixedPrice,
        address minting,
        address refund,
        address fees,
        address escrow
    ) {
        // Deploy all auxiliary contracts
        (
            fixedPrice,
            minting,
            refund,
            fees,
            escrow
        ) = auxiliaryFactory.deployAuxiliaryContracts(
            _stoAddress,
            _params.securityToken,
            _params.investmentToken,
            _params.rate,
            _params.fundsReceiver,
            _params.feeRate,
            _params.feeWallet
        );
        
        // Initialize the STO with the auxiliary contracts
        ICappedSTO sto = ICappedSTO(_stoAddress);
        sto.configureWithContracts(
            _params.startTime,
            _params.endTime,
            _params.hardCap,
            _params.softCap,
            _params.rate,
            _params.fundsReceiver,
            _params.investmentToken,
            fixedPrice,
            minting,
            refund,
            escrow,
            fees
        );
        
        return (fixedPrice, minting, refund, fees, escrow);
    }
    
    /**
     * @dev Store deployment information
     */
    function _storeDeploymentInfo(
        bytes32 _deploymentId,
        address _sto,
        address _securityToken,
        address _fixedPrice,
        address _minting,
        address _refund,
        address _fees,
        address _escrow
    ) private {
        STODeploymentInfo memory deploymentInfo = STODeploymentInfo({
            sto: _sto,
            securityToken: _securityToken,
            fixedPrice: _fixedPrice,
            minting: _minting,
            refund: _refund,
            fees: _fees,
            escrow: _escrow
        });
        
        deployments[_deploymentId] = deploymentInfo;
        allDeploymentIds.push(_deploymentId);
    }
    
    /**
     * @dev Set a new STO implementation address
     * @param _newImplementation Address of the new implementation
     */
    function setSTOImplementation(address _newImplementation) external onlyOwner {
        require(_newImplementation != address(0), "New implementation cannot be zero");
        stoImplementation = _newImplementation;
    }
    
    /**
     * @dev Set a new auxiliary factory address
     * @param _newAuxiliaryFactory Address of the new auxiliary factory
     */
    function setAuxiliaryFactory(address _newAuxiliaryFactory) external onlyOwner {
        require(_newAuxiliaryFactory != address(0), "New auxiliary factory cannot be zero");
        auxiliaryFactory = STOAuxiliaryFactory(_newAuxiliaryFactory);
    }
    
    /**
     * @dev Get deployment info by ID
     * @param _deploymentId The deployment ID
     * @return Deployment information
     */
    function getDeploymentInfo(bytes32 _deploymentId) external view returns (STODeploymentInfo memory) {
        return deployments[_deploymentId];
    }
    
    /**
     * @dev Get the total number of deployments
     * @return Total number of deployments
     */
    function getDeploymentCount() external view returns (uint256) {
        return allDeploymentIds.length;
    }
    
    /**
     * @dev Get a range of deployment IDs
     * @param _start Start index
     * @param _count Number of items to return
     * @return Array of deployment IDs
     */
    function getDeploymentIds(uint256 _start, uint256 _count) external view returns (bytes32[] memory) {
        require(_start < allDeploymentIds.length, "Start index out of bounds");
        require(_count > 0, "Count must be greater than zero");
        
        uint256 end = _start + _count;
        if (end > allDeploymentIds.length) {
            end = allDeploymentIds.length;
        }
        
        bytes32[] memory result = new bytes32[](end - _start);
        for (uint256 i = _start; i < end; i++) {
            result[i - _start] = allDeploymentIds[i];
        }
        
        return result;
    }
}

/**
 * @title ICappedSTO interface
 * @dev Minimal interface for CappedSTO to avoid conversion issues
 */
interface ICappedSTO {
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
    ) external;
}