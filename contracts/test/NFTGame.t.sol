// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";
import "../src/NFTGame/Pool.sol";
import "../src/NFTGame/PriceOracle.sol";
import "../src/NFTGame/RandomNumberGenerator.sol";
import "./TestERC20.sol";
import "./TestERC721.sol";

contract NFTGame is Test {
    Pool pool;
    PriceOracle oracle;
    RandomNumberGenerator random;
    TestERC20 erc20;
    TestERC721 erc721;

    address richard = makeAddr("richard"); // Funder
    uint256 tokenId = 1;
    uint256 erc20amount = 1e18;

    function setUp() public {
        oracle = new PriceOracle();
        random = new RandomNumberGenerator();
        pool = new Pool(oracle, random);
        erc20 = new TestERC20("USDC", "USDC", 6);
        erc721 = new TestERC721("CryptoKitties", "CK");
        erc20.mint(richard, erc20amount);
        erc721.mint(richard, tokenId);
        oracle.setERC20Price(address(erc20), 1e18);
        oracle.setERC721Price(address(erc721), tokenId, 1e18);
        oracle.setEthPrice(1);
    }

    function testE2E() public {
        vm.startPrank(richard);
        vm.deal(richard, 1e50);
        erc20.approve(address(pool), erc20amount);
        erc721.approve(address(pool), tokenId);
        address[] memory erc20s = new address[](1);
        erc20s[0] = address(erc20);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = erc20amount;
        address[] memory erc721s = new address[](1);
        erc721s[0] = address(erc721);
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = tokenId;

        pool.depositAll{value: 1e18}(erc20s, amounts, erc721s, tokenIds);

        pool.spin();

        pool.withdrawAll(erc20s, amounts, erc721s, tokenIds);
    }
}
