// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";
import "../src/core/EntryPoint.sol";
import "../src/P256Account.sol";
import "../src/P256AccountFactory.sol";
import {UserOperation} from "../src/interfaces/UserOperation.sol";

/**
 * @title CounterTest
 * @author richard@fun.xyz
 * @notice This is a sanity test for the account function.
 * We want to be able to send a userOp through the entrypoint and have it execute
 */
contract CounterTest is Test {
    Counter public counter;
    EntryPoint public entryPoint;
    P256AccountFactory public accountFactory;
    P256Account public account;

    // -------------------- 🧑‍🍼 Account Creation Constants 🧑‍🍼 --------------------
    bytes constant publicKey = "iliketturtles";
    bytes32 constant salt = keccak256("iwanttoberichardwhenigrowup");
    address richard = makeAddr("richard"); // Funder

    /**
     * Deploy the Entrypoint, AccountFactory, and a single account
     * Deposit eth into the entrypoint on behalf of the account to pay for gas
     */
    function setUp() public {
        counter = new Counter();
        entryPoint = new EntryPoint();
        accountFactory = new P256AccountFactory(entryPoint);
        bytes memory constructorArgs = abi.encode(entryPoint, publicKey);
        bytes memory initializationCode = abi.encodePacked(
            type(P256Account).creationCode,
            constructorArgs
        );
        account = accountFactory.createAccount(publicKey);
        vm.deal(richard, 1e50);
        vm.prank(richard);
        entryPoint.depositTo{value: 1e18}(address(account));
    }

    /**
     * Check the account was created correctly with the correct parameters
     */
    function testCreation() public {
        assertEq(account.getNonce(), 0);
        assertEq(account.publicKey(), publicKey);
    }

    /**
     * Create a userOp that increments the counter and send it through the entrypoint
     */
    function testUserOpE2E() public {
        assertEq(counter.number(), 0);
        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: entryPoint.getNonce(address(account), 0),
            initCode: "",
            callData: "",
            callGasLimit: 10_000_000,
            verificationGasLimit: 10_000_000,
            preVerificationGas: 1_000_000,
            maxFeePerGas: 10_000_000,
            maxPriorityFeePerGas: 10_000_000,
            paymasterAndData: "",
            signature: ""
        });
        userOp.callData = abi.encodeWithSelector(
            account.execute.selector,
            address(counter),
            0,
            abi.encodeWithSelector(counter.increment.selector)
        );
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, payable(richard));
        assertEq(counter.number(), 1);
    }
}
