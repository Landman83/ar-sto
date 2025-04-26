// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";


/**
 * @title tUSD Token
 * @dev A simple ERC20 token that can be minted on demand by the owner
 */
contract TUSD is ERC20, Ownable {
    constructor() ERC20("Test USD", "tUSD") Ownable(msg.sender) {}


    /**
     * @dev Mints tokens to a specified address
     * @param to The address that will receive the minted tokens
     * @param amount The amount of tokens to mint
     */
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
