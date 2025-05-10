// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/ISignedWithdraw.sol";
import "../interfaces/ISTO.sol";
import "../libraries/Withdrawal.sol";
import "../libraries/Errors.sol";
import "../libraries/Events.sol";

/**
 * @title SignedWithdraw
 * @notice Implementation for gasless withdrawals via EIP-712 signatures
 * @dev Investors sign withdrawal requests off-chain that operators can submit on their behalf
 */
contract SignedWithdraw is ISignedWithdraw, Ownable, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    // Use the WITHDRAWAL_TYPEHASH from the Withdrawal library
    bytes32 public constant WITHDRAWAL_TYPEHASH = Withdrawal.WITHDRAWAL_TYPEHASH;
    
    // Mapping of investor to nonce (for replay protection)
    mapping(address => uint256) private _nonces;
    
    // Mapping of operator status
    mapping(address => bool) private _operators;
    
    // STO contract that processes the actual withdrawals
    address public stoContract;
    
    /**
     * @dev Constructor for SignedWithdraw
     * @param name The name to use in the EIP-712 domain
     * @param version The version to use in the EIP-712 domain
     * @param _stoContract The STO contract address
     */
    constructor(string memory name, string memory version, address _stoContract) 
        EIP712(name, version)
        Ownable(msg.sender)
    {
        require(_stoContract != address(0), Errors.ZERO_ADDRESS);
        stoContract = _stoContract;
        
        // Add deployer as the first operator
        _operators[msg.sender] = true;
        emit Events.OperatorAdded(msg.sender, msg.sender);
    }
    
    /**
     * @notice Execute a signed withdrawal
     * @param withdrawal The withdrawal details signed by the investor
     * @param signature The EIP-712 signature from the investor
     */
    function executeSignedWithdrawal(
        Withdrawal.WithdrawalInfo calldata withdrawal,
        bytes calldata signature
    ) external override nonReentrant {
        // Verify operator status
        require(_operators[msg.sender], Errors.NOT_AUTHORIZED_OPERATOR);
        
        // Verify the investor's signature
        require(isValidSignature(withdrawal, signature, withdrawal.investor), Errors.INVALID_SIGNATURE);
        
        // Verify the nonce
        require(_nonces[withdrawal.investor] == withdrawal.nonce, Errors.INVALID_NONCE);
        
        // Increment the nonce
        _nonces[withdrawal.investor]++;
        
        // Verify withdrawal parameters
        require(withdrawal.withdrawalAmount > 0, Errors.ZERO_INVESTMENT);
        
        // Check if the STO is closed or finalized
        bool isClosed;
        bool isFinalized;
        
        try ISTO(stoContract).isSTOClosed() returns (bool closed) {
            isClosed = closed;
        } catch {
            // If the function doesn't exist, assume it's not closed
            isClosed = false;
        }
        
        require(!isClosed, Errors.CLOSED);
        
        try ISTO(stoContract).isEscrowFinalized() returns (bool finalized) {
            isFinalized = finalized;
        } catch {
            // If the function doesn't exist, assume it's not finalized
            isFinalized = false;
        }
        
        require(!isFinalized, Errors.ESCROW_ALREADY_FINALIZED);
        
        // Process the withdrawal
        // We use a try/catch because the STO might revert if conditions aren't met
        try ISTO(stoContract).withdrawInvestment(withdrawal.withdrawalAmount) {
            // Withdrawal successful
            emit Events.SignedWithdrawalExecuted(
                withdrawal.investor,
                withdrawal.withdrawalAmount,
                withdrawal.nonce,
                msg.sender
            );
        } catch Error(string memory reason) {
            revert(reason);
        } catch {
            revert(Errors.INVALID_OPERATION);
        }
    }
    
    /**
     * @notice Add a new operator
     * @param operator The operator address to add
     */
    function addOperator(address operator) external onlyOwner {
        require(!_operators[operator], "Already an operator");
        _operators[operator] = true;
        emit Events.OperatorAdded(operator, msg.sender);
    }
    
    /**
     * @notice Remove an operator
     * @param operator The operator address to remove
     */
    function removeOperator(address operator) external onlyOwner {
        require(_operators[operator], "Not an operator");
        _operators[operator] = false;
        emit Events.OperatorRemoved(operator, msg.sender);
    }
    
    /**
     * @notice Check if an operator is authorized
     * @param operator The operator address to check
     * @return Whether the operator is authorized
     */
    function isOperator(address operator) external view returns (bool) {
        return _operators[operator];
    }
    
    /**
     * @notice Get the current nonce for an investor
     * @param investor The investor address
     * @return The current nonce for the investor
     */
    function getNonce(address investor) external view override returns (uint256) {
        return _nonces[investor];
    }
    
    /**
     * @notice Get the domain separator for EIP-712
     * @return The domain separator
     */
    function getDomainSeparator() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }
    
    /**
     * @notice Get the type hash for WithdrawalInfo
     * @return The type hash
     */
    function getWithdrawalTypeHash() external pure override returns (bytes32) {
        return WITHDRAWAL_TYPEHASH;
    }
    
    /**
     * @notice Hash a withdrawal using EIP-712
     * @param withdrawal The withdrawal to hash
     * @return The EIP-712 hash of the withdrawal
     */
    function hashWithdrawal(Withdrawal.WithdrawalInfo calldata withdrawal) public view override returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(abi.encode(
                WITHDRAWAL_TYPEHASH,
                withdrawal.investor,
                withdrawal.investmentToken,
                withdrawal.withdrawalAmount,
                withdrawal.nonce
            ))
        );
    }
    
    /**
     * @notice Verify a signature against a withdrawal
     * @param withdrawal The withdrawal that was signed
     * @param signature The signature to verify
     * @param expectedSigner The address that should have signed the withdrawal
     * @return True if the signature is valid, false otherwise
     */
    function isValidSignature(
        Withdrawal.WithdrawalInfo calldata withdrawal,
        bytes calldata signature,
        address expectedSigner
    ) public view override returns (bool) {
        bytes32 withdrawalHash = hashWithdrawal(withdrawal);
        address recoveredSigner = recoverSigner(withdrawalHash, signature);
        return recoveredSigner == expectedSigner;
    }
    
    /**
     * @notice Recover the signer from a signature and hash
     * @param hash The hash that was signed
     * @param signature The signature bytes
     * @return The recovered signer address
     */
    function recoverSigner(bytes32 hash, bytes calldata signature) public pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        
        // EIP-2 standardized the signature format
        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "Invalid signature 'v' value");
        
        return ecrecover(hash, v, r, s);
    }
    
    /**
     * @notice Update the STO contract address
     * @param _stoContract The new STO contract address
     */
    function setSTOContract(address _stoContract) external onlyOwner {
        require(_stoContract != address(0), Errors.ZERO_ADDRESS);
        stoContract = _stoContract;
    }
}