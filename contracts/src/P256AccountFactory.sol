// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "./P256Account.sol";

/**
 * A sample factory contract for P256Account
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this sample factory).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */
contract P256AccountFactory {
    P256Account public immutable accountImplementation;
    IEntryPoint public immutable entryPoint;
    address public snarkVerifier;

    constructor(IEntryPoint _entryPoint, address _snarkVerifier) {
        accountImplementation = new P256Account(_entryPoint);
        entryPoint = _entryPoint;
        snarkVerifier = _snarkVerifier;
    }

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     */
    function createAccount(
        bytes memory publicKey
    ) public returns (P256Account ret) {
        address addr = getAddress(publicKey);
        uint codeSize = addr.code.length;
        if (codeSize > 0) {
            return P256Account(payable(addr));
        }
        ret = P256Account(
            payable(
                new ERC1967Proxy{salt: bytes32(keccak256(publicKey))}(
                    address(accountImplementation),
                    abi.encodeCall(
                        P256Account.initialize,
                        (entryPoint, publicKey, snarkVerifier)
                    )
                )
            )
        );
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(bytes memory publicKey) public view returns (address) {
        return
            Create2.computeAddress(
                bytes32(keccak256(publicKey)),
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            address(accountImplementation),
                            abi.encodeCall(
                                P256Account.initialize,
                                (entryPoint, publicKey, snarkVerifier)
                            )
                        )
                    )
                )
            );
    }
}
