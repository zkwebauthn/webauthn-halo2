// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./interfaces/IPriceOracle.sol";

/**
 * @title PriceOracle
 * @notice Gets all prices for amount of ERC20 and ERC721
 */
contract PriceOracle is IPriceOracle {
    mapping(address => uint256) public ERC20Price;
    mapping(address => mapping(uint256 => uint256)) public ERC721Price;
    mapping(address => uint256) public ERC721FloorPrice;
    uint256 ethPrice;

    uint256 constant DIVISOR = 1e18; // No Fractions

    function getERC20Price(
        address token,
        uint256 amount
    ) external view returns (uint256) {
        return (ERC20Price[token] * amount) / DIVISOR;
    }

    function getEthPrice(uint256 amount) external view returns (uint256) {
        return (ethPrice * amount) / DIVISOR;
    }

    function getERC721Price(
        address token,
        uint256 tokenId
    ) external view returns (uint256) {
        uint256 price = ERC721Price[token][tokenId] / DIVISOR;
        uint256 floorPrice = ERC721FloorPrice[token] / DIVISOR;
        return price > floorPrice ? price : floorPrice;
    }

    function setERC20Price(address token, uint256 price) external {
        require(price / DIVISOR > 0, "Price must be greater than 0");
        ERC20Price[token] = price;
    }

    function setEthPrice(uint256 price) external {
        require(price / DIVISOR > 0, "Price must be greater than 0");
        ethPrice = price;
    }

    function setERC721Price(
        address token,
        uint256 tokenId,
        uint256 price
    ) external {
        require(price / DIVISOR > 0, "Price must be greater than 0");
        ERC721Price[token][tokenId] = price;
    }

    function setERC721FloorPrice(address token, uint256 price) external {
        require(price / DIVISOR > 0, "Price must be greater than 0");
        ERC721FloorPrice[token] = price;
    }
}
