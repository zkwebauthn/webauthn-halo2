// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";
import "../src/core/EntryPoint.sol";
import "../src/P256Account.sol";
import "../src/P256AccountFactory.sol";

contract CounterTest is Test {
    Counter public counter;
    EntryPoint public entryPoint;
    P256AccountFactory public accountFactory;
    address public account;

    function setUp() public {
        // Deploy EntryPoint
        entryPoint = new EntryPoint();
        // Deploy Account Factory
        accountFactory = new P256AccountFactory();
        // Deploy Account
        uint256 salt = 0;
        bytes memory args = abi.encode(entryPoint, "");
        bytes memory bytecode = abi.encodePacked(
            type(P256Account).creationCode,
            args
        );
        account = accountFactory.create(salt, bytecode);
        counter = new Counter();
    }

    function testCounter() public {
        // Create a userOp that calls counter to increment it
        assertEq(P256Account(payable(account)).nonce(), 0);
    }
}
