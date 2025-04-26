// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../proxy/STOProxy.sol";
import "../CappedSTO.sol";
import "../interfaces/ISTO.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Auxiliary component imports
import "../mixins/FixedPrice.sol";
import "../utils/Minting.sol";
import "../utils/Refund.sol";
import "../utils/Escrow.sol";
import "../utils/Fees.sol";

/**
 * @title Consolidated STO Factory
 * @dev Factory for deploying complete STO setups including all auxiliary contracts
 * This factory consolidates the functionality of both STOFactory and STOAuxiliaryFactory
 * to simplify the deployment process and reduce the number of contracts.
 */
contract STOFactory is Ownable {
    // STO implementation contract
    address public stoImplementation;
    
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
    
    // Event emitted when a complete set of auxiliary contracts is deployed
    event AuxiliaryContractsDeployed(
        address indexed sto,
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
    
    // Auxiliary deployment parameters
    struct AuxiliaryParams {
        address sto;
        address securityToken;
        address investmentToken;
        address payable fundsReceiver;
        uint256 rate;
        address feesAddress;
    }
    
    // Mapping of deployment ID to deployment info
    mapping(bytes32 => STODeploymentInfo) public deployments;
    
    // Array to track all deployment IDs
    bytes32[] public allDeploymentIds;
    
    /**
     * @dev Constructor to set up the STO factory
     * @param _stoImplementation Address of the STO implementation contract
     */
    constructor(address _stoImplementation) Ownable(msg.sender) {
        require(_stoImplementation != address(0), "STO implementation cannot be zero");
        stoImplementation = _stoImplementation;
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
        ) = deployAuxiliaryContracts(
            stoAddress,
            _params.securityToken,
            _params.investmentToken,
            _params.rate,
            _params.fundsReceiver,
            _params.feeRate,
            _params.feeWallet
        );
        
        // 3. Initialize the STO with the auxiliary contracts
        ICappedSTO sto = ICappedSTO(stoAddress);
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
     * @notice Deploy auxiliary contracts for an STO
     * @param _sto Address of the STO contract
     * @param _securityToken Address of the security token
     * @param _investmentToken Address of the investment token
     * @param _rate Token conversion rate
     * @param _fundsReceiver Address to receive funds
     * @param _feeRate Fee rate in basis points (optional)
     * @param _feeWallet Fee wallet address (optional)
     * @return fixedPrice Address of the fixed price contract
     * @return minting Address of the minting contract
     * @return refund Address of the refund contract
     * @return fees Address of the fees contract (address(0) if not created)
     * @return escrow Address of the escrow contract
     */
    function deployAuxiliaryContracts(
        address _sto,
        address _securityToken,
        address _investmentToken,
        uint256 _rate,
        address payable _fundsReceiver,
        uint256 _feeRate,
        address _feeWallet
    ) public returns (
        address fixedPrice,
        address minting,
        address refund,
        address fees,
        address escrow
    ) {
        // Validate inputs
        require(_sto != address(0), "STO address cannot be zero");
        require(_securityToken != address(0), "Security token address cannot be zero");
        require(_investmentToken != address(0), "Investment token address cannot be zero");
        require(_fundsReceiver != address(0), "Funds receiver address cannot be zero");
        require(_rate > 0, "Rate must be greater than zero");

        // Deploy the fixed price contract
        fixedPrice = _deployFixedPrice(_sto, _securityToken, _rate);
        
        // Deploy the minting, refund, and fees contracts
        (minting, refund, fees) = _deployInvestmentContracts(
            _sto, 
            _investmentToken, 
            _feeRate, 
            _feeWallet
        );
        
        // Group parameters to avoid stack too deep error
        AuxiliaryParams memory params = AuxiliaryParams({
            sto: _sto,
            securityToken: _securityToken,
            investmentToken: _investmentToken,
            fundsReceiver: _fundsReceiver,
            rate: _rate,
            feesAddress: fees
        });
        
        // Deploy escrow and update references
        escrow = _deployEscrowAndUpdateReferences(params, minting, refund);
        
        // Emit event with all deployed contract addresses
        emit AuxiliaryContractsDeployed(
            _sto,
            fixedPrice,
            minting,
            refund,
            fees,
            escrow
        );
        
        return (fixedPrice, minting, refund, fees, escrow);
    }
    
    /**
     * @dev Deploy the fixed price contract
     * @param _sto Address of the STO contract
     * @param _securityToken Address of the security token
     * @param _rate Token conversion rate
     * @return Address of the deployed fixed price contract
     */
    function _deployFixedPrice(
        address _sto,
        address _securityToken,
        uint256 _rate
    ) private returns (address) {
        FixedPrice fixedPriceLogic = new FixedPrice(
            _securityToken,
            _rate,
            _sto
        );
        return address(fixedPriceLogic);
    }
    
    /**
     * @dev Deploy the minting, refund, and fees contracts
     * @param _sto Address of the STO contract
     * @param _investmentToken Address of the investment token
     * @param _feeRate Fee rate in basis points
     * @param _feeWallet Fee wallet address
     * @return minting Address of the deployed minting contract
     * @return refund Address of the deployed refund contract
     * @return fees Address of the deployed fees contract (address(0) if not created)
     */
    function _deployInvestmentContracts(
        address _sto,
        address _investmentToken,
        uint256 _feeRate,
        address _feeWallet
    ) private returns (
        address minting,
        address refund,
        address fees
    ) {
        // Deploy minting contract
        Minting mintingContract = new Minting(_sto);
        minting = address(mintingContract);
        
        // Deploy refund contract
        Refund refundContract = new Refund(_sto, _investmentToken, _sto);
        refund = address(refundContract);
        
        // Deploy fees contract if fee parameters are provided
        fees = address(0);
        if (_feeRate > 0 && _feeWallet != address(0)) {
            Fees feesContract = new Fees(_feeRate, _feeWallet, _sto);
            fees = address(feesContract);
        }
        
        return (minting, refund, fees);
    }
    
    /**
     * @dev Deploy the escrow contract and update references
     * @param _params Deployment parameters
     * @param _minting Address of the minting contract
     * @param _refund Address of the refund contract
     * @return Address of the deployed escrow contract
     */
    function _deployEscrowAndUpdateReferences(
        AuxiliaryParams memory _params,
        address _minting,
        address _refund
    ) private returns (address) {
        // Deploy the escrow contract
        Escrow escrowContract = new Escrow(
            _params.sto,
            _params.securityToken,
            _params.investmentToken,
            _params.fundsReceiver,
            _refund,
            _minting,
            _params.feesAddress
        );
        address escrow = address(escrowContract);
        
        // Update contracts with correct references after escrow is deployed
        Minting(_minting).updateEscrow(escrow);
        Refund(_refund).updateEscrow(escrow);
        
        return escrow;
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
    
    // Add a storage gap for safe upgradeability
    uint256[50] private __gap;
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