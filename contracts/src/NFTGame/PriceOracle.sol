// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./interfaces/IPriceOracle.sol";

contract PriceOracle is IPriceOracle {
    mapping(address => uint256) public ERC20Price;
    mapping(address => mapping(uint256 => uint256)) public ERC721Price;
    uint256 ethPrice;

    function getERC20Price(
        address token,
        uint256 amount
    ) external view returns (uint256) {
        return ERC20Price[token] * amount;
    }

    function getEthPrice(uint256 amount) external view returns (uint256) {
        return ethPrice;
    }

    function getERC721Price(
        address token,
        uint256 tokenId
    ) external view returns (uint256) {
        return ERC721Price[token][tokenId];
    }

    function setERC20Price(address token, uint256 price) external {
        ERC20Price[token] = price;
    }

    function setEthPrice(uint256 amount) external {
        ethPrice = amount;
    }

    function setERC721Price(
        address token,
        uint256 tokenId,
        uint256 price
    ) external {
        ERC721Price[token][tokenId] = price;
    }
}
