// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.17;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestERC20 is ERC20 {
    uint8 immutable tokenDecimals;

    constructor(
        string memory name,
        string memory symbol,
        uint8 _decimals
    ) ERC20(name, symbol) {
        tokenDecimals = _decimals;
        _mint(msg.sender, 1e6 * 10 ** tokenDecimals);
    }

    function decimals() public view override returns (uint8) {
        return tokenDecimals;
    }

    /**
     * Sends 1 million tokens to sender
     * @param recipient Reciever of the newly minted tokens
     */
    function airdrop(address recipient) public {
        _mint(recipient, 1e6 * 10 ** tokenDecimals);
    }

    /**
     * Mints tokens to the specified address
     * @param to Reciever of the newly minted tokens
     * @param amount Amount of tokens to mint
     * @return true if mint was successful
     */
    function mint(address to, uint256 amount) public returns (bool) {
        _mint(to, amount);
        return true;
    }
}
