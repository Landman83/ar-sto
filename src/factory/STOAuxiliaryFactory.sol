// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../mixins/FixedPrice.sol";
import "../utils/Minting.sol";
import "../utils/Refund.sol";
import "../utils/Escrow.sol";
import "../utils/Fees.sol";

/**
 * @title Factory for deploying STO auxiliary contracts
 * @dev This factory deploys all the auxiliary contracts needed for an STO
 * These contracts are deployed separately to reduce the deployment size of the main STO contract
 */
contract STOAuxiliaryFactory {
    // Event emitted when a complete set of auxiliary contracts is deployed
    event AuxiliaryContractsDeployed(
        address indexed sto,
        address fixedPrice,
        address minting,
        address refund,
        address fees,
        address escrow
    );

    // Store deployment parameters temporarily
    struct DeploymentParams {
        address sto;
        address securityToken;
        address investmentToken;
        address payable fundsReceiver;
        uint256 rate;
        address feesAddress;
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
    ) external returns (
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
        DeploymentParams memory params = DeploymentParams({
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
        DeploymentParams memory _params,
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
}