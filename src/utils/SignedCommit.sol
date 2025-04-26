// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/ISignedCommit.sol";

/**
 * @title SignedCommit
 * @notice Implementation for gasless token commitments via EIP-712 signatures
 * @dev Investors sign commitments off-chain that operators can submit on their behalf
 */
contract SignedCommit is ISignedCommit, Ownable, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    // Type hash for EIP-712 Commitment struct
    bytes32 public constant COMMITMENT_TYPEHASH = keccak256(
        "Commitment(address investor,address token,uint256 amount,uint256 nonce)"
    );
    
    // Mapping of investor to nonce (for replay protection)
    mapping(address => uint256) private _nonces;
    
    // Mapping of operator status
    mapping(address => bool) private _operators;
    
    // Mapping of accepted tokens
    mapping(address => bool) private _acceptedTokens;
    
    // Mapping of investor => token => committed amount
    mapping(address => mapping(address => uint256)) private _commitments;
    
    // Mapping of token => total committed amount
    mapping(address => uint256) private _totalCommitments;
    
    /**
     * @dev Constructor for SignedCommit
     * @param name The name to use in the EIP-712 domain
     * @param version The version to use in the EIP-712 domain
     */
    constructor(string memory name, string memory version) 
        EIP712(name, version)
        Ownable(msg.sender)
    {
        // Add deployer as the first operator
        _operators[msg.sender] = true;
        emit OperatorAdded(msg.sender);
    }
    
    /**
     * @notice Execute a signed commitment
     * @dev Any operator can execute this on behalf of the investor
     * @param commitment The commitment details signed by the investor
     * @param signature The EIP-712 signature from the investor
     */
    function executeSignedCommitment(
        Commitment calldata commitment,
        bytes calldata signature
    ) external override nonReentrant {
        // Verify operator status
        require(_operators[msg.sender], "Not an operator");
        
        // Verify token is accepted
        require(_acceptedTokens[commitment.token], "Token not accepted");
        
        // Verify the investor's signature
        require(_verifySignature(commitment, signature), "Invalid signature");
        
        // Verify the nonce
        require(_nonces[commitment.investor] == commitment.nonce, "Invalid nonce");
        
        // Increment the nonce
        _nonces[commitment.investor]++;
        
        // Transfer tokens from investor to this contract
        IERC20(commitment.token).safeTransferFrom(
            commitment.investor,
            address(this),
            commitment.amount
        );
        
        // Update commitment records
        _commitments[commitment.investor][commitment.token] += commitment.amount;
        _totalCommitments[commitment.token] += commitment.amount;
        
        // Emit event
        emit CommitmentExecuted(
            commitment.investor,
            commitment.token,
            commitment.amount,
            commitment.nonce,
            msg.sender
        );
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
     * @notice Check if an operator is authorized
     * @param operator The operator address to check
     * @return Whether the operator is authorized
     */
    function isOperator(address operator) external view override returns (bool) {
        return _operators[operator];
    }
    
    /**
     * @notice Add a new operator
     * @param operator The operator address to add
     */
    function addOperator(address operator) external override onlyOwner {
        require(!_operators[operator], "Already an operator");
        _operators[operator] = true;
        emit OperatorAdded(operator);
    }
    
    /**
     * @notice Remove an operator
     * @param operator The operator address to remove
     */
    function removeOperator(address operator) external override onlyOwner {
        require(_operators[operator], "Not an operator");
        _operators[operator] = false;
        emit OperatorRemoved(operator);
    }
    
    /**
     * @notice Check if a token is accepted
     * @param token The token address to check
     * @return Whether the token is accepted
     */
    function isAcceptedToken(address token) external view override returns (bool) {
        return _acceptedTokens[token];
    }
    
    /**
     * @notice Add an accepted token
     * @param token The token address to add
     */
    function addAcceptedToken(address token) external override onlyOwner {
        require(token != address(0), "Zero address");
        require(!_acceptedTokens[token], "Token already accepted");
        _acceptedTokens[token] = true;
    }
    
    /**
     * @notice Get the domain separator for EIP-712
     * @return The domain separator
     */
    function getDomainSeparator() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }
    
    /**
     * @notice Get the type hash for Commitment
     * @return The type hash
     */
    function getCommitmentTypeHash() external pure override returns (bytes32) {
        return COMMITMENT_TYPEHASH;
    }
    
    /**
     * @notice Check the balance of tokens committed by an investor
     * @param investor The investor address
     * @param token The token address
     * @return The amount of tokens committed
     */
    function getCommitment(address investor, address token) external view override returns (uint256) {
        return _commitments[investor][token];
    }
    
    /**
     * @notice Get total commitments for a token
     * @param token The token address
     * @return The total amount of tokens committed
     */
    function getTotalCommitments(address token) external view override returns (uint256) {
        return _totalCommitments[token];
    }
    
    /**
     * @notice Withdraw tokens (only callable by owner)
     * @param token The token address
     * @param amount The amount to withdraw
     * @param recipient The recipient address
     */
    function withdrawTokens(address token, uint256 amount, address recipient) external override onlyOwner {
        require(recipient != address(0), "Zero recipient address");
        require(amount > 0, "Zero amount");
        require(amount <= _totalCommitments[token], "Amount exceeds total commitments");
        
        // Update total commitments
        _totalCommitments[token] -= amount;
        
        // Transfer tokens to recipient
        IERC20(token).safeTransfer(recipient, amount);
        
        emit TokensWithdrawn(token, amount, recipient);
    }
    
    /**
     * @notice Verify EIP-712 signature for a commitment
     * @param commitment The commitment to verify
     * @param signature The signature bytes
     * @return Whether the signature is valid
     */
    function _verifySignature(
        Commitment calldata commitment,
        bytes calldata signature
    ) internal view returns (bool) {
        bytes32 structHash = keccak256(abi.encode(
            COMMITMENT_TYPEHASH,
            commitment.investor,
            commitment.token,
            commitment.amount,
            commitment.nonce
        ));
        
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, signature);
        
        return signer == commitment.investor;
    }
}