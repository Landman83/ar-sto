// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title MathHelpers
 * @dev Contract module that provides common math utilities
 */
library MathHelpers {
    /**
     * @dev Calculate the token amount based on the investment amount and rate
     * @param investmentAmount Amount of investment tokens
     * @param rate Rate of tokens per investment token (multiplied by 10^18)
     * @return tokens Number of tokens to be issued
     */
    function calculateTokenAmount(uint256 investmentAmount, uint256 rate) internal pure returns (uint256) {
        return investmentAmount * rate / (10 ** 18);
    }

    /**
     * @dev Calculate the investment amount required for a given token amount
     * @param tokenAmount Amount of tokens
     * @param rate Rate of tokens per investment token (multiplied by 10^18)
     * @return investmentAmount Amount of investment tokens required
     */
    function calculateInvestmentAmount(uint256 tokenAmount, uint256 rate) internal pure returns (uint256) {
        return tokenAmount * (10 ** 18) / rate;
    }

    /**
     * @dev Calculate the refund amount when actual tokens are less than expected
     * @param investmentAmount Original investment amount
     * @param expectedTokens Expected number of tokens
     * @param actualTokens Actual number of tokens (after cap/granularity adjustments)
     * @param rate Rate of tokens per investment token (multiplied by 10^18)
     * @return refundAmount Amount to be refunded
     */
    function calculateRefund(
        uint256 investmentAmount,
        uint256 expectedTokens,
        uint256 actualTokens,
        uint256 rate
    ) internal pure returns (uint256) {
        if (actualTokens >= expectedTokens) {
            return 0;
        }

        uint256 actualCost = calculateInvestmentAmount(actualTokens, rate);
        return investmentAmount - actualCost;
    }

    /**
     * @dev Safely convert a uint256 to a negative int256 for use in decreasing operations
     * @param amount The unsigned amount to convert to a negative int256
     * @return The negative signed integer result
     * @notice This function will revert if amount is greater than the maximum
     * int256 value (2^255 - 1) to prevent overflow when negating
     */
    function toNegativeInt(uint256 amount) internal pure returns (int256) {
        // Ensure the amount can be safely converted to int256 and negated
        // 2^255 - 1 is the maximum value for int256
        require(amount <= uint256(type(int256).max), "Amount too large for safe conversion");

        // First convert to int256, then negate
        return -int256(amount);
    }
}