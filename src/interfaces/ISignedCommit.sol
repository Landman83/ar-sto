// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title ISignedCommit
 * @notice Interface for signed commitment functionality
 * @dev Allows users to sign commitments off-chain that can be submitted by operators
 */
interface ISignedCommit {
    /**
     * @notice Commitment data structure for signed orders
     * @param investor The address of the investor making the commitment
     * @param token The ERC20 token address used for the commitment
     * @param amount The amount of tokens being committed
     * @param nonce The investor's nonce to prevent replay attacks
     */
    struct Commitment {
        address investor;
        address token;
        uint256 amount; 
        uint256 nonce;
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
    ) external;
    
    /**
     * @notice Get the current nonce for an investor
     * @param investor The investor address
     * @return The current nonce for the investor
     */
    function getNonce(address investor) external view returns (uint256);
    
    /**
     * @notice Check if an operator is authorized
     * @param operator The operator address to check
     * @return Whether the operator is authorized
     */
    function isOperator(address operator) external view returns (bool);
    
    /**
     * @notice Add a new operator
     * @param operator The operator address to add
     */
    function addOperator(address operator) external;
    
    /**
     * @notice Remove an operator
     * @param operator The operator address to remove
     */
    function removeOperator(address operator) external;
    
    /**
     * @notice Check if a token is accepted
     * @param token The token address to check
     * @return Whether the token is accepted
     */
    function isAcceptedToken(address token) external view returns (bool);
    
    /**
     * @notice Add an accepted token
     * @param token The token address to add
     */
    function addAcceptedToken(address token) external;
    
    /**
     * @notice Get the domain separator for EIP-712
     * @return The domain separator
     */
    function getDomainSeparator() external view returns (bytes32);
    
    /**
     * @notice Get the type hash for Commitment
     * @return The type hash
     */
    function getCommitmentTypeHash() external view returns (bytes32);
    
    /**
     * @notice Check the balance of tokens committed by an investor
     * @param investor The investor address
     * @param token The token address
     * @return The amount of tokens committed
     */
    function getCommitment(address investor, address token) external view returns (uint256);
    
    /**
     * @notice Get total commitments for a token
     * @param token The token address
     * @return The total amount of tokens committed
     */
    function getTotalCommitments(address token) external view returns (uint256);
    
    /**
     * @notice Withdraw tokens (only callable by owner)
     * @param token The token address
     * @param amount The amount to withdraw
     * @param recipient The recipient address
     */
    function withdrawTokens(address token, uint256 amount, address recipient) external;
    
    /**
     * @dev Emitted when a new commitment is executed
     */
    event CommitmentExecuted(
        address indexed investor,
        address indexed token,
        uint256 amount,
        uint256 nonce,
        address operator
    );
    
    /**
     * @dev Emitted when an operator is added
     */
    event OperatorAdded(address indexed operator);
    
    /**
     * @dev Emitted when an operator is removed
     */
    event OperatorRemoved(address indexed operator);
    
    /**
     * @dev Emitted when tokens are withdrawn
     */
    event TokensWithdrawn(
        address indexed token,
        uint256 amount,
        address indexed recipient
    );
}