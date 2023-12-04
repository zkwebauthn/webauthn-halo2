// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./erc-4337/core/BasePaymaster.sol";

/**
 * Paymaster that pays for everything, given the user is authorized.
 * Based on contract provided by Ethereum Foundation and Visa Crypto
 */
contract SponsorPaymaster is BasePaymaster {
    mapping(address => bool) public authorized; //whitelist for paymaster access

    constructor(IEntryPoint _entryPoint) BasePaymaster(_entryPoint) {
        _transferOwnership(msg.sender);
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
        // Leaving this commented out for now until a bundler supports custom tx.origin stuff
        // require(authorized[tx.origin], "User is not authorized.");

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
