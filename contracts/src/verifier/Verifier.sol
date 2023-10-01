// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract Verifier is Ownable2Step {
    mapping(address => bytes) public challenges;
    address public snarkVerifier;

    constructor(address _snarkVerifier){
        snarkVerifier = _snarkVerifier;
    }

	// Stores the public key for an account
	function registerNewPasskey(address account, bytes memory expectedChallenge) external onlyOwner {
        challenges[account] = expectedChallenge;
    }

	// Makes a call to Verifier checking the proof vs the account's public key
	// returns true if proof matches public key
	function verifyPasskeySignature(address account, bytes memory proof) external returns(bool){
        (bool success,) = snarkVerifier.call(abi.encode(challenges[account], proof));
        return success;
    }
}
