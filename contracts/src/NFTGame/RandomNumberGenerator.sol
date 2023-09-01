// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./interfaces/IRandomNumberGenerator.sol";

contract RandomNumberGenerator is IRandomNumberGenerator {
    uint256 number;

    function getRandomNumber() external view returns (uint256) {
        return number;
    }

    function setRandomNumber(uint256 _number) external {
        number = _number;
    }
}
