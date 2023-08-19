// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./core/BasePaymaster.sol";

/**
 * Paymaster that pays for everything, given the user is authorized.
 * Based on contract provided by Ethereum Foundation.
 */
contract SponsorPaymaster is BasePaymaster {
    mapping(address => bool) private authorized; //whitelist for paymaster access

    constructor(IEntryPoint _entryPoint) BasePaymaster(_entryPoint) {
        // to support "deterministic address" factory
        // solhint-disable avoid-tx-origin
        if (tx.origin != msg.sender) {
            _transferOwnership(tx.origin);
        }
    }

    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    )
        internal
        view
        virtual
        override
        returns (bytes memory context, uint256 validationData)
    {
        //Check if the user is authorized to use the paymaster.
        // address user = userOp.sender;
        // require(authorized[user], "User is not authorized.");

        (userOp, userOpHash, maxCost);
        return ("", 0); //There is no paymaster data to send (e.g., time range)
    }

    //Functions to read/write whitelist
    //Only paymaster owner can write
    function addAuthorizedUser(address user) public onlyOwner {
        authorized[user] = true;
    }

    function removeAuthorizedUser(address user) public onlyOwner {
        authorized[user] = false;
    }

    function isAuthorized(address user) public view returns (bool) {
        return authorized[user];
    }
}
